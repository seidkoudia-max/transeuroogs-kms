#!/usr/bin/env python3
"""Idempotent, state-preserving installation of the isolated service lab."""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
from service_profile import NAMESPACE, NODES, TOPOLOGY, config

ROOT = Path('/opt/transeuroogs')
RELEASE = ROOT / 'service-release'
STATE = ROOT / 'services-state'
LABELS = {'transeuroogs.lab': 'true', 'transeuroogs.profile': 'services-v1'}


def kube(*args, data=None):
    return subprocess.check_output(['sudo', 'microk8s', 'kubectl', *args], input=data, text=True)


def apply(items):
    print(kube('apply', '-f', '-', data=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': items})), end='')


def private_write(path, data):
    with open(path, 'x', opener=lambda p, f: os.open(p, f, 0o600)) as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())


def owned(namespace, expected):
    obj = json.loads(kube('get', 'namespace', namespace, '--ignore-not-found', '-o', 'json') or '{}')
    if obj and any(obj['metadata'].get('labels', {}).get(k) != v for k, v in expected.items()):
        raise RuntimeError('Namespace is not owned by this profile: ' + namespace)
    return bool(obj)


def secret(name, namespace, files):
    return {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': name, 'namespace': namespace, 'labels': LABELS},
            'type': 'Opaque', 'data': {k: base64.b64encode(v).decode() for k, v in files.items()}}


def pvc(name, namespace):
    return {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'metadata': {'name': name, 'namespace': namespace, 'labels': LABELS},
            'spec': {'accessModes': ['ReadWriteOnce'], 'resources': {'requests': {'storage': '64Mi'}}}}


def workload(name, namespace, image, command, mounts, volumes, replicas=1, ports=None):
    label = dict(LABELS, app=name)
    container = {'name': 'server', 'image': image, 'command': command,
                 'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
                 'resources': {'requests': {'cpu': '25m', 'memory': '32Mi'}, 'limits': {'cpu': '500m', 'memory': '256Mi'}},
                 'volumeMounts': mounts}
    if ports: container['ports'] = ports
    return {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': name, 'namespace': namespace, 'labels': LABELS},
            'spec': {'replicas': replicas, 'strategy': {'type': 'Recreate'}, 'selector': {'matchLabels': label},
                     'template': {'metadata': {'labels': label}, 'spec': {'automountServiceAccountToken': False,
                                  'containers': [container], 'volumes': volumes}}}}


def endpoint(name, image):
    conf = config(name)
    count = 64 if name == 'windhof' else (128 if name.startswith('link-') else 0)
    script = ('count=' + str(count) + '; if [ -e /state/private/state.enc ]; then count=0; fi; '
              'exec /bin/kms --config=/config/kms.json --listen=0.0.0.0:8443 --pki-dir=/run/pki '
              '--certificate-name=' + name + ' --synthetic-keys="$count" --synthetic-ttl=24h')
    pod = workload(name, NAMESPACE, image, ['/bin/sh', '-ec', script],
        [{'name': n, 'mountPath': p, 'readOnly': n != 'state'} for n, p in [('state', '/state'), ('private', '/run/private'), ('pki', '/run/pki'), ('config', '/config')]],
        [{'name': 'state', 'persistentVolumeClaim': {'claimName': name + '-state'}},
         {'name': 'private', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '1Mi'}},
         {'name': 'signing', 'secret': {'secretName': name + '-signing', 'defaultMode': 0o440}},
         {'name': 'pki', 'secret': {'secretName': name + '-pki', 'defaultMode': 0o440}},
         {'name': 'config', 'configMap': {'name': name + '-config'}}], ports=[{'containerPort': 8443}])
    spec = pod['spec']['template']['spec']
    spec['securityContext'] = {'runAsUser': 65532, 'runAsGroup': 65532, 'fsGroup': 65532}
    spec['containers'][0]['securityContext']['readOnlyRootFilesystem'] = True
    spec['containers'][0]['readinessProbe'] = {'tcpSocket': {'port': 8443}}
    spec['initContainers'] = [{'name': 'private-state', 'image': image, 'command': ['/bin/sh', '-ec',
        'umask 077; mkdir -p /state/private /private/material; chmod 700 /state/private /private/material; '
        'cp /signing/signing.key.pem /private/material/signing.key.pem; chmod 600 /private/material/signing.key.pem'],
        'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
        'volumeMounts': [{'name': 'state', 'mountPath': '/state'}, {'name': 'private', 'mountPath': '/private'}, {'name': 'signing', 'mountPath': '/signing', 'readOnly': True}]}]
    adjacent = list(conf.get('inter_kms', {}).get('peers', {}))
    if name.startswith('link-'):
        link = next(l for l in TOPOLOGY['links'] if l['provider'] == name)
        adjacent = [link['source'], link['target']]
    policy = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy', 'metadata': {'name': name + '-ingress', 'namespace': NAMESPACE},
        'spec': {'podSelector': {'matchLabels': {'app': name}}, 'policyTypes': ['Ingress'], 'ingress': [{'from': [
            {'podSelector': {'matchExpressions': [{'key': 'app', 'operator': 'In', 'values': adjacent}]}},
            {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'tfs'}}, 'podSelector': {'matchExpressions': [
                {'key': 'app', 'operator': 'In', 'values': ['deviceservice', 'services-operator', 'services-adapter', 'services-test']}]}}],
            'ports': [{'protocol': 'TCP', 'port': 8443}]}]}}
    # Geographic peers reach their independently consumed link-key provider too.
    return [pvc(name + '-state', NAMESPACE),
            {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': name + '-config', 'namespace': NAMESPACE}, 'data': {'kms.json': json.dumps(conf)}},
            {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': name, 'namespace': NAMESPACE},
             'spec': {'selector': {'app': name}, 'ports': [{'name': 'https', 'port': 8443, 'targetPort': 8443}]}}, pod, policy]


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('action', choices=['install', 'start-adapter']); args = parser.parse_args()
    if socket.gethostname() != 'lima-transeuroogs-tfs': raise RuntimeError('Dedicated VM required')
    if not owned('tfs', {'transeuroogs.lab': 'true'}): raise RuntimeError('Base TeraFlow lab is absent')
    exists = owned(NAMESPACE, LABELS)
    STATE.mkdir(mode=0o700, exist_ok=True)
    if args.action == 'start-adapter':
        if not exists: raise RuntimeError('Service lab is absent')
        print(kube('-n', 'tfs', 'scale', 'deployment/services-adapter', '--replicas=1')); return
    images = json.loads((STATE / 'images.json').read_text())
    names = list(NODES) + [l['provider'] for l in TOPOLOGY['links']]
    fingerprint = hashlib.sha256(json.dumps({n: config(n) for n in names}, sort_keys=True).encode()).hexdigest()
    marker = STATE / 'config-binding'
    if marker.exists() and marker.read_text() != fingerprint: raise RuntimeError('Existing journals require unchanged configuration')
    if not marker.exists():
        if exists: raise RuntimeError('Existing namespace lacks its configuration record; inspect before recovery')
        private_write(marker, fingerprint)
    # Configurations are validated before any cluster mutation.
    for name in names:
        path = STATE / (name + '.json'); path.write_text(json.dumps(config(name)))
        subprocess.run([str(RELEASE / 'bin/kms'), '--config=' + str(path), '--validate-config'], check=True, stdout=subprocess.DEVNULL)
    pki = STATE / 'pki'
    if not pki.exists(): subprocess.run([str(RELEASE / 'bin/test-pki'), '--profile=services', '--out=' + str(pki)], check=True)
    apply([{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NAMESPACE, 'labels': LABELS}}])
    for name in names:
        signing = STATE / (name + '.sign.pem')
        if not signing.exists(): subprocess.run([str(RELEASE / 'bin/kms-metadata'), 'keygen', '--private=' + str(signing), '--public=' + str(STATE / (name + '.pub.pem'))], check=True, stdout=subprocess.DEVNULL)
        apply([secret(name + '-signing', NAMESPACE, {'signing.key.pem': signing.read_bytes()}),
               secret(name + '-pki', NAMESPACE, {f: (pki / f).read_bytes() for f in ['ca.crt.pem', name + '.crt.pem', name + '.key.pem']})])
        apply(endpoint(name, images['kms']))
    def credentials(role, certs):
        files = ['ca.crt.pem'] + [name + suffix for name in certs for suffix in ['.crt.pem', '.key.pem']]
        apply([secret('services-' + role, 'tfs', {f: (pki / f).read_bytes() for f in files})])
    credentials('controller', ['controller-sae'])
    credentials('observer', ['observer-sae'])
    credentials('adapter', ['adapter-sae'])
    credentials('test', ['controller-sae', 'observer-sae', 'adapter-sae', 'protection-sae', 'unknown-sae', 'sae-windhof', 'sae-betzdorf'] + list(NODES))
    existing = json.loads(kube('-n', 'tfs', 'get', 'deployment', 'deviceservice', '-o', 'json'))
    backup = STATE / 'previous-device-template.json'
    if not backup.exists(): private_write(backup, json.dumps(existing['spec']['template']))
    server = existing['spec']['template']['spec']['containers'][0]['name']
    patch = {'spec': {'template': {'spec': {'volumes': [{'name': 'services-controller', 'secret': {'secretName': 'services-controller', 'defaultMode': 0o400}}],
        'containers': [{'name': server, 'image': images['device'], 'volumeMounts': [{'name': 'services-controller', 'mountPath': '/run/transeuroogs/services', 'readOnly': True}]}]}}}}
    print(kube('-n', 'tfs', 'patch', 'deployment', 'deviceservice', '--type=strategic', '--patch', json.dumps(patch)), end='')
    for role, action in [('operator', 'monitor'), ('adapter', 'adapter-loop'), ('test', 'idle')]:
        claim = 'services-' + role + '-state'; credential = 'observer' if role == 'operator' else role
        apply([pvc(claim, 'tfs'), workload('services-' + role, 'tfs', images['device'], ['python', '/opt/transeuroogs-services/runtime.py', action],
            [{'name': 'credentials', 'mountPath': '/run/services', 'readOnly': True}, {'name': 'state', 'mountPath': '/state'}],
            [{'name': 'credentials', 'secret': {'secretName': 'services-' + credential, 'defaultMode': 0o400}}, {'name': 'state', 'persistentVolumeClaim': {'claimName': claim}}],
            replicas=0 if role == 'adapter' else 1, ports=[{'containerPort': 8080}] if role == 'operator' else None)])
    apply([{'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'services-operator', 'namespace': 'tfs'},
            'spec': {'selector': {'app': 'services-operator'}, 'ports': [{'name': 'http', 'port': 8080, 'targetPort': 8080}]}}])
    # Internal read-only status, no public ingress or mutation endpoint.
    apply([{'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy', 'metadata': {'name': 'services-operator', 'namespace': 'tfs'},
            'spec': {'podSelector': {'matchLabels': {'app': 'services-operator'}}, 'policyTypes': ['Ingress'], 'ingress': [
                {'from': [{'podSelector': {'matchLabels': {'app': 'services-test'}}}], 'ports': [{'protocol': 'TCP', 'port': 8080}]}]}}])
    (STATE / 'installed.json').write_text(json.dumps({'config_binding': fingerprint, 'images': images}))
    print('Installed service profile; no existing KMS journal or PVC was reset.')


if __name__ == '__main__': main()
