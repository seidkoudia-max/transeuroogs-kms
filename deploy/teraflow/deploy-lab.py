#!/usr/bin/env python3
"""Apply the isolated synthetic lab without deleting namespaces or persisted state.

Run inside lima-transeuroogs-tfs. Upstream manifests remain in the pinned Linux
checkout; adaptations here are for the local lab, not an ETSI conformance profile.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import uuid

import yaml

ROOT = Path('/opt/transeuroogs')
SOURCE = ROOT / 'controller'
STATE = ROOT / 'lab-state'
OWNER = {'transeuroogs.lab': 'true'}
COMPONENTS = ('context', 'device', 'pathcomp', 'qkd_app', 'service', 'nbi', 'webui')


def run(args, *, data=None, capture=True):
    return subprocess.run(args, input=data, text=True, check=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def kube(*args, data=None):
    return run(['sudo', 'microk8s', 'kubectl', *args], data=data)


def apply(objects):
    if objects:
        print(kube('apply', '-f', '-', data=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': objects})), end='')


def namespace(name):
    existing = json.loads(kube('get', 'namespace', name, '--ignore-not-found', '-o', 'json') or '{}')
    if existing and existing['metadata'].get('labels', {}).get('transeuroogs.lab') != 'true':
        raise RuntimeError('Refusing to modify a namespace not owned by this lab: ' + name)
    apply([{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': name, 'labels': OWNER}}])


def require_owned(name):
    existing = json.loads(kube('get', 'namespace', name, '--ignore-not-found', '-o', 'json') or '{}')
    if existing.get('metadata', {}).get('labels', {}).get('transeuroogs.lab') != 'true':
        raise RuntimeError('Run prerequisites first; namespace is absent or not lab-owned: ' + name)


def secret(name, namespace, values):
    return {'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
            'metadata': {'name': name, 'namespace': namespace},
            'data': {k: base64.b64encode(v if isinstance(v, bytes) else v.encode()).decode()
                     for k, v in values.items()}}


def persistent_password():
    path = STATE / 'database-password'
    if not path.exists():
        with open(path, 'x', opener=lambda p, flags: os.open(p, flags, 0o600)) as stream:
            stream.write(secrets.token_hex(24))
    return path.read_text().strip()


def image_digest(tag, arch=None):
    if arch:
        run(['sudo', 'docker', 'pull', '--platform=linux/' + arch, tag])
    info = json.loads(run(['sudo', 'docker', 'image', 'inspect', tag]))[0]
    digest = info['RepoDigests'][0]
    if arch:
        manifest = json.loads(run(['sudo', 'docker', 'buildx', 'imagetools', 'inspect', '--raw', digest]))
        if 'manifests' in manifest:
            entry = next(m for m in manifest['manifests'] if m.get('platform', {}).get('architecture') == arch
                         and m.get('platform', {}).get('os') == 'linux')
            digest = digest.split('@')[0] + '@' + entry['digest']
    return digest


def prerequisites():
    for name in ('tfs', 'crdb', 'nats', 'kafka', 'transeuroogs-kms'):
        namespace(name)
    password = persistent_password()
    apply([secret('crdb-data', 'tfs', {'CRDB_NAMESPACE': 'crdb', 'CRDB_SQL_PORT': '26257',
                                    'CRDB_USERNAME': 'tfs', 'CRDB_PASSWORD': password, 'CRDB_SSLMODE': 'require'}),
           secret('nats-data', 'tfs', {'NATS_NAMESPACE': 'nats', 'NATS_CLIENT_PORT': '4222'}),
           secret('crdb-bootstrap', 'crdb', {'COCKROACH_PASSWORD': password}),
           # Upstream NBI creates topics during startup, even in this small lab.
           secret('kfk-kpi-data', 'tfs', {'KFK_NAMESPACE': 'kafka', 'KFK_SERVER_PORT': '9092'})])

    crdb_image = image_digest('cockroachdb/cockroach:latest-v22.2', 'amd64')
    # Upstream's bootstrap generates certificates in the container filesystem.
    # Persist those separately so a restart cannot strand an initialized database.
    apply([{'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim',
            'metadata': {'name': 'crdb-certs', 'namespace': 'crdb'},
            'spec': {'accessModes': ['ReadWriteOnce'], 'resources': {'requests': {'storage': '1Mi'}}}}])
    objects = list(yaml.safe_load_all((SOURCE / 'manifests/cockroachdb/single-node.yaml').read_text()))
    for obj in objects:
        obj['metadata']['namespace'] = 'crdb'
        if obj['kind'] != 'StatefulSet':
            continue
        spec = obj['spec']['template']['spec']
        spec['automountServiceAccountToken'] = False
        spec['volumes'] = [{'name': 'certs', 'persistentVolumeClaim': {'claimName': 'crdb-certs'}}]
        spec['initContainers'] = [{'name': 'prepare-certificates', 'image': crdb_image,
            'command': ['/bin/bash', '-euc',
                'umask 077; chmod 700 /certs; '
                'if [ ! -e /certs/ca.crt ]; then '
                '/cockroach/cockroach cert create-ca --certs-dir=/certs --ca-key=/certs/ca.key; fi; '
                'if [ ! -e /certs/client.root.crt ]; then '
                '/cockroach/cockroach cert create-client root --certs-dir=/certs --ca-key=/certs/ca.key; fi; '
                'if [ ! -e /certs/node.crt ]; then '
                '/cockroach/cockroach cert create-node localhost 127.0.0.1 cockroachdb-public '
                'cockroachdb-public.crdb.svc.cluster.local --certs-dir=/certs --ca-key=/certs/ca.key; fi'],
            'volumeMounts': [{'name': 'certs', 'mountPath': '/certs'}]}]
        server = spec['containers'][0]
        server['image'] = crdb_image
        server['args'] += ['--cache=256MiB', '--max-sql-memory=256MiB']
        server['env'] = [{'name': 'COCKROACH_DATABASE', 'value': 'tfs_context'},
                         {'name': 'COCKROACH_USER', 'value': 'tfs'},
                         {'name': 'COCKROACH_PASSWORD', 'valueFrom': {'secretKeyRef': {
                             'name': 'crdb-bootstrap', 'key': 'COCKROACH_PASSWORD'}}}]
        server['volumeMounts'] = [{'name': 'data', 'mountPath': '/cockroach/cockroach-data'},
                                 {'name': 'certs', 'mountPath': '/cockroach/certs'}]
        obj['spec']['volumeClaimTemplates'] = [{'metadata': {'name': 'data'}, 'spec': {
            'accessModes': ['ReadWriteOnce'], 'resources': {'requests': {'storage': '3Gi'}}}}]
    apply(objects)

    nats_image = image_digest('nats:2.10-alpine', 'arm64')
    labels = {'app': 'nats'}
    apply([{'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': 'nats', 'namespace': 'nats'},
            'spec': {'replicas': 1, 'selector': {'matchLabels': labels}, 'template': {
                'metadata': {'labels': labels}, 'spec': {'automountServiceAccountToken': False, 'containers': [{
                    'name': 'nats', 'image': nats_image, 'args': ['-m', '8222'],
                    'ports': [{'containerPort': 4222}],
                    'readinessProbe': {'tcpSocket': {'port': 4222}},
                    'resources': {'requests': {'cpu': '50m', 'memory': '64Mi'},
                                  'limits': {'cpu': '500m', 'memory': '256Mi'}}}]}}}},
           {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'nats', 'namespace': 'nats'},
            'spec': {'selector': labels, 'ports': [{'name': 'client', 'port': 4222, 'targetPort': 4222}]}}])
    (STATE / 'dependency-images.json').write_text(json.dumps({'cockroachdb': crdb_image, 'nats': nats_image}, indent=2))
    kafka()


def kafka():
    namespace('kafka')
    apply([secret('kfk-kpi-data', 'tfs', {'KFK_NAMESPACE': 'kafka', 'KFK_SERVER_PORT': '9092'})])
    cluster_file = STATE / 'kafka-cluster-id'
    if not cluster_file.exists():
        with cluster_file.open('x') as stream:
            stream.write(base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip('='))
    kafka_image = image_digest('apache/kafka:3.9.1', 'arm64')
    labels = {'app': 'kafka'}
    config = {
        'CLUSTER_ID': cluster_file.read_text().strip(),
        'KAFKA_NODE_ID': '1', 'KAFKA_PROCESS_ROLES': 'broker,controller',
        'KAFKA_LISTENERS': 'PLAINTEXT://:9092,CONTROLLER://:9093',
        'KAFKA_ADVERTISED_LISTENERS': 'PLAINTEXT://kafka-service.kafka.svc.cluster.local:9092',
        'KAFKA_LISTENER_SECURITY_PROTOCOL_MAP': 'CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT',
        'KAFKA_CONTROLLER_LISTENER_NAMES': 'CONTROLLER',
        'KAFKA_INTER_BROKER_LISTENER_NAME': 'PLAINTEXT',
        'KAFKA_CONTROLLER_QUORUM_VOTERS': '1@localhost:9093',
        'KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR': '1',
        'KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR': '1',
        'KAFKA_TRANSACTION_STATE_LOG_MIN_ISR': '1',
        'KAFKA_LOG_DIRS': '/var/lib/kafka/data/logs',
        'KAFKA_LOG_RETENTION_HOURS': '1', 'KAFKA_LOG_RETENTION_BYTES': '16777216',
        'KAFKA_LOG_SEGMENT_BYTES': '8388608', 'KAFKA_NUM_PARTITIONS': '1',
        'KAFKA_HEAP_OPTS': '-Xms256m -Xmx512m',
    }
    apply([{'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'kafka-service', 'namespace': 'kafka'},
            'spec': {'selector': labels, 'ports': [{'name': 'client', 'port': 9092, 'targetPort': 9092}]}},
           {'apiVersion': 'apps/v1', 'kind': 'StatefulSet', 'metadata': {'name': 'kafka', 'namespace': 'kafka'},
            'spec': {'replicas': 1, 'serviceName': 'kafka-service', 'selector': {'matchLabels': labels},
                'template': {'metadata': {'labels': labels}, 'spec': {
                    'automountServiceAccountToken': False, 'securityContext': {'fsGroup': 1000},
                    'containers': [{'name': 'kafka', 'image': kafka_image,
                        'env': [{'name': key, 'value': value} for key, value in config.items()],
                        'ports': [{'containerPort': 9092}],
                        'startupProbe': {'tcpSocket': {'port': 9092}, 'periodSeconds': 3, 'failureThreshold': 100},
                        'readinessProbe': {'tcpSocket': {'port': 9092}},
                        'resources': {'requests': {'cpu': '100m', 'memory': '512Mi'},
                                      'limits': {'cpu': '1', 'memory': '1Gi'}},
                        'volumeMounts': [{'name': 'data', 'mountPath': '/var/lib/kafka/data'}]}]}},
                'volumeClaimTemplates': [{'metadata': {'name': 'data'}, 'spec': {
                    'accessModes': ['ReadWriteOnce'], 'resources': {'requests': {'storage': '1Gi'}}}}]}}])
    image_file = STATE / 'dependency-images.json'
    previous = json.loads(image_file.read_text()) if image_file.exists() else {}
    image_file.write_text(json.dumps(dict(previous, kafka=kafka_image), indent=2))


def controller(components=COMPONENTS):
    images = {}
    objects = []
    for component in components:
        for obj in yaml.safe_load_all((SOURCE / ('manifests/' + component + 'service.yaml')).read_text()):
            if not obj or obj['kind'] in ('HorizontalPodAutoscaler', 'PersistentVolumeClaim'):
                continue
            obj['metadata']['namespace'] = 'tfs'
            if obj['kind'] == 'Deployment':
                obj['spec']['replicas'] = 1
                spec = obj['spec']['template']['spec']
                spec['automountServiceAccountToken'] = False
                # Grafana/observability is separate from the bounded allocation lab.
                spec['containers'] = [c for c in spec['containers'] if c['name'] != 'grafana']
                spec.pop('volumes', None)
                for server in spec['containers']:
                    image_name = server['image'].split('/')[-1].split(':')[0]
                    tag = 'localhost:32000/tfs/' + image_name + ':transeuroogs-v7'
                    # Select the amd64 child manifest explicitly: the Kubernetes
                    # node is arm64, and Rosetta executes these Intel containers.
                    images[image_name] = image_digest(tag, 'amd64')
                    server['image'] = images[image_name]
                    server['imagePullPolicy'] = 'IfNotPresent'
                    if component == 'webui':
                        # Direct loopback forwarding has no ingress prefix rewrite.
                        for setting in server.get('env', []):
                            if setting['name'] == 'WEBUISERVICE_SERVICE_BASEURL_HTTP':
                                setting['value'] = '/'
                    if 'startupProbe' in server:
                        server['startupProbe'].update({'periodSeconds': 3, 'failureThreshold': 100, 'timeoutSeconds': 3})
                    for name in ('readinessProbe', 'livenessProbe'):
                        if name in server:
                            server[name]['timeoutSeconds'] = 3
                    if component == 'device':
                        server['volumeMounts'] = [{'name': 'kms-management-mtls', 'mountPath': '/run/transeuroogs/mtls', 'readOnly': True}]
                        spec['volumes'] = [{'name': 'kms-management-mtls', 'secret': {'secretName': 'kms-management-mtls', 'defaultMode': 0o400}}]
            elif component == 'webui' and obj['kind'] == 'Service':
                obj['spec']['ports'] = [p for p in obj['spec']['ports'] if p['name'] == 'webui']
            objects.append(obj)
    # All Services precede Deployments so discovery environment variables exist at pod start.
    objects.sort(key=lambda obj: obj['kind'] != 'Service')
    apply(objects)
    image_file = STATE / 'controller-images.json'
    previous = json.loads(image_file.read_text()) if image_file.exists() else {}
    image_file.write_text(json.dumps(dict(previous, **images), indent=2))


def kms():
    pki = STATE / 'pki'
    if not pki.exists():
        run([str(ROOT / 'bin/test-pki'), '--out=' + str(pki)], capture=False)
    signing = STATE / 'signing.key.pem'
    if not signing.exists():
        run([str(ROOT / 'bin/kms-metadata'), 'keygen', '--private', str(signing),
             '--public', str(STATE / 'signing.pub.pem')], capture=False)
    apply([secret('kms-server', 'transeuroogs-kms', {name: (pki / name).read_bytes()
           for name in ('ca.crt.pem', 'kms.crt.pem', 'kms.key.pem')}),
           secret('kms-signing', 'transeuroogs-kms', {'signing.key.pem': signing.read_bytes()}),
           secret('kms-management-mtls', 'tfs', {'ca.crt.pem': (pki / 'ca.crt.pem').read_bytes(),
                  'controller.crt.pem': (pki / 'controller-sae.crt.pem').read_bytes(),
                  'controller.key.pem': (pki / 'controller-sae.key.pem').read_bytes()}),
           secret('kms-lab-clients', 'tfs', {name: (pki / name).read_bytes() for name in (
               'ca.crt.pem', 'controller-sae.crt.pem', 'controller-sae.key.pem',
               'sae-lu.crt.pem', 'sae-lu.key.pem', 'sae-gr.crt.pem', 'sae-gr.key.pem',
               'unknown-sae.crt.pem', 'unknown-sae.key.pem')})])
    config = json.loads((ROOT / 'kms/deploy/config/sdn-local.json').read_text())
    config['metadata']['signing_key_file'] = '/run/kms-private/material/signing.key.pem'
    config['metadata']['state_dir'] = '/state/private'
    rule = config['sdn']['applications'][0]['rule']
    rule['max_generation_age_seconds'] = 43200
    rule['max_local_age_seconds'] = 43200
    apply([{'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'kms-config', 'namespace': 'transeuroogs-kms'},
            'data': {'kms.json': json.dumps(config)}},
           {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'metadata': {'name': 'kms-state', 'namespace': 'transeuroogs-kms'},
            'spec': {'accessModes': ['ReadWriteOnce'], 'resources': {'requests': {'storage': '1Gi'}}}}])
    image = image_digest('localhost:32000/transeuroogs/kms:lab', 'arm64')
    spec = {'automountServiceAccountToken': False,
            'securityContext': {'runAsUser': 65532, 'runAsGroup': 65532, 'fsGroup': 65532},
            'initContainers': [{'name': 'prepare-private-files', 'image': image,
                'command': ['/bin/sh', '-ec', 'umask 077; mkdir -p /state/private /private/material; '
                            'chmod 700 /state/private /private/material; '
                            'cp /signing-input/signing.key.pem /private/material/signing.key.pem; '
                            'chmod 600 /private/material/signing.key.pem'],
                'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
                'volumeMounts': [{'name': 'state', 'mountPath': '/state'},
                                {'name': 'private', 'mountPath': '/private'},
                                {'name': 'signing', 'mountPath': '/signing-input', 'readOnly': True}]}],
            'containers': [{'name': 'kms', 'image': image,
                'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                    'capabilities': {'drop': ['ALL']}},
                'ports': [{'containerPort': 8443}], 'readinessProbe': {'tcpSocket': {'port': 8443}},
                'resources': {'requests': {'cpu': '50m', 'memory': '64Mi'}, 'limits': {'cpu': '500m', 'memory': '256Mi'}},
                'volumeMounts': [{'name': name, 'mountPath': path, 'readOnly': name != 'state'} for name, path in (
                    ('state', '/state'), ('config', '/config'), ('pki', '/run/kms-pki'), ('private', '/run/kms-private'))]}],
            'volumes': [{'name': 'state', 'persistentVolumeClaim': {'claimName': 'kms-state'}},
                        {'name': 'private', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '1Mi'}},
                        {'name': 'config', 'configMap': {'name': 'kms-config'}},
                        {'name': 'pki', 'secret': {'secretName': 'kms-server', 'defaultMode': 0o440}},
                        {'name': 'signing', 'secret': {'secretName': 'kms-signing', 'defaultMode': 0o440}}]}
    apply([{'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': 'kms', 'namespace': 'transeuroogs-kms'},
            'spec': {'replicas': 1, 'strategy': {'type': 'Recreate'}, 'selector': {'matchLabels': {'app': 'kms'}},
                     'template': {'metadata': {'labels': {'app': 'kms'}}, 'spec': spec}}},
           {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'kms', 'namespace': 'transeuroogs-kms'},
            'spec': {'selector': {'app': 'kms'}, 'ports': [{'name': 'https', 'port': 8443, 'targetPort': 8443}]}},
           {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'kms', 'namespace': 'tfs'},
            'spec': {'type': 'ExternalName', 'externalName': 'kms.transeuroogs-kms.svc.cluster.local'}}])
    (STATE / 'kms-image.json').write_text(json.dumps({'image': image}))
    # Namespace and pod identity constrain reachability; mTLS remains mandatory.
    apply([{'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
            'metadata': {'name': 'kms-ingress', 'namespace': 'transeuroogs-kms'},
            'spec': {'podSelector': {'matchLabels': {'app': 'kms'}}, 'policyTypes': ['Ingress'],
                     'ingress': [{'from': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'tfs'}},
                         'podSelector': {'matchExpressions': [{'key': 'app', 'operator': 'In',
                                                              'values': ['deviceservice', 'lab-client']}]}}],
                         'ports': [{'protocol': 'TCP', 'port': 8443}]}]}}])


def client():
    image = json.loads((STATE / 'controller-images.json').read_text())['device']
    apply([{'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim',
            'metadata': {'name': 'policy-outbox', 'namespace': 'tfs'},
            'spec': {'accessModes': ['ReadWriteOnce'], 'resources': {'requests': {'storage': '1Mi'}}}}])
    apply([{'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': 'lab-client', 'namespace': 'tfs'},
            'spec': {'replicas': 1, 'strategy': {'type': 'Recreate'}, 'selector': {'matchLabels': {'app': 'lab-client'}}, 'template': {
                'metadata': {'labels': {'app': 'lab-client'}}, 'spec': {
                    'automountServiceAccountToken': False,
                    'containers': [{'name': 'client', 'image': image,
                        'command': ['python', '-c', 'import time; time.sleep(86400)'],
                        'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
                        'resources': {'requests': {'cpu': '50m', 'memory': '64Mi'},
                                      'limits': {'cpu': '500m', 'memory': '256Mi'}},
                        'volumeMounts': [{'name': 'clients', 'mountPath': '/run/lab-clients', 'readOnly': True},
                                         {'name': 'outbox', 'mountPath': '/state'}]}],
                    'volumes': [{'name': 'clients', 'secret': {'secretName': 'kms-lab-clients', 'defaultMode': 0o400}},
                                {'name': 'outbox', 'persistentVolumeClaim': {'claimName': 'policy-outbox'}}]}}}}])


def probe():
    namespace('transeuroogs-probe')
    image = json.loads((STATE / 'controller-images.json').read_text())['device']
    name = 'network-probe-' + uuid.uuid4().hex[:8]
    command = ('import socket,sys\n'
               'address=socket.gethostbyname("kms.transeuroogs-kms.svc.cluster.local")\n'
               'try:\n socket.create_connection((address,8443),timeout=3).close()\n'
               'except socket.timeout:\n print("PASS: unrelated namespace cannot reach KMS")\n'
               'else:\n sys.exit("FAIL: unrelated namespace reached KMS")\n')
    apply([{'apiVersion': 'batch/v1', 'kind': 'Job', 'metadata': {'name': name, 'namespace': 'transeuroogs-probe'},
            'spec': {'backoffLimit': 0, 'activeDeadlineSeconds': 45, 'template': {'spec': {
                'restartPolicy': 'Never', 'automountServiceAccountToken': False,
                'containers': [{'name': 'probe', 'image': image, 'command': ['python', '-c', command],
                    'resources': {'requests': {'cpu': '50m', 'memory': '32Mi'},
                                  'limits': {'cpu': '250m', 'memory': '128Mi'}}}]}}}}])
    try:
        print(kube('-n', 'transeuroogs-probe', 'wait', '--for=condition=complete', 'job/' + name, '--timeout=50s'), end='')
        print(kube('-n', 'transeuroogs-probe', 'logs', 'job/' + name), end='')
    finally:
        kube('-n', 'transeuroogs-probe', 'delete', 'job', name, '--wait=false')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('prerequisites', 'kafka', 'kms', 'controller', 'client', 'probe'))
    parser.add_argument('--components', nargs='+', choices=COMPONENTS, default=COMPONENTS)
    args = parser.parse_args()
    if socket.gethostname() != 'lima-transeuroogs-tfs':
        raise SystemExit('Run only inside the dedicated TeraFlow Lima VM.')
    if args.stage != 'prerequisites':
        require_owned('tfs')
        require_owned('transeuroogs-kms')
    STATE.mkdir(mode=0o700, exist_ok=True)
    if args.stage == 'controller':
        controller(args.components)
    else:
        {'prerequisites': prerequisites, 'kafka': kafka, 'kms': kms, 'client': client, 'probe': probe}[args.stage]()


if __name__ == '__main__':
    main()
