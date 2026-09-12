#!/usr/bin/env python3
"""Install four synthetic endpoints alongside the existing TeraFlow lab."""
import importlib.util
import json
from pathlib import Path
import socket

from lux_profile import NAMESPACE, NODES, config

spec = importlib.util.spec_from_file_location('tfs_lab', Path(__file__).resolve().parents[1] / 'teraflow/deploy-lab.py')
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
ROOT = Path('/opt/transeuroogs')
DATA = ROOT / 'lux-lab-state'


def pvc(name, namespace, size='16Mi'):
    return {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'metadata': {'name': name, 'namespace': namespace},
            'spec': {'accessModes': ['ReadWriteOnce'], 'resources': {'requests': {'storage': size}}}}


def endpoint(name, image):
    label = {'app': name, 'transeuroogs.lab': 'true'}
    seed = '64' if name == 'windhof' else '0'
    command = ('count=' + seed + '; if [ -e /state/private/state.enc ]; then count=0; fi; '
               'exec /bin/kms --config=/config/kms.json --listen=0.0.0.0:8443 '
               '--pki-dir=/run/pki --certificate-name=' + name + ' --synthetic-keys="$count" --synthetic-ttl=1h')
    pod = {'automountServiceAccountToken': False,
        'securityContext': {'runAsUser': 65532, 'runAsGroup': 65532, 'fsGroup': 65532},
        'initContainers': [{'name': 'private-state', 'image': image, 'command': ['/bin/sh', '-ec',
            'umask 077; mkdir -p /state/private /private/material; chmod 700 /state/private /private/material; '
            'cp /signing/signing.key.pem /private/material/signing.key.pem; chmod 600 /private/material/signing.key.pem'],
            'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
            'volumeMounts': [{'name': 'state', 'mountPath': '/state'}, {'name': 'private', 'mountPath': '/private'},
                            {'name': 'signing', 'mountPath': '/signing', 'readOnly': True}]}],
        'containers': [{'name': 'kms', 'image': image, 'command': ['/bin/sh', '-ec', command],
            'ports': [{'containerPort': 8443}], 'readinessProbe': {'tcpSocket': {'port': 8443}},
            'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                'capabilities': {'drop': ['ALL']}},
            'resources': {'requests': {'cpu': '50m', 'memory': '64Mi'}, 'limits': {'cpu': '500m', 'memory': '256Mi'}},
            'volumeMounts': [{'name': n, 'mountPath': path, 'readOnly': n != 'state'} for n, path in (
                ('state', '/state'), ('private', '/run/private'), ('pki', '/run/pki'), ('config', '/config'))]}],
        'volumes': [{'name': 'state', 'persistentVolumeClaim': {'claimName': name + '-state'}},
                    {'name': 'private', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '1Mi'}},
                    {'name': 'signing', 'secret': {'secretName': name + '-signing', 'defaultMode': 0o440}},
                    {'name': 'pki', 'secret': {'secretName': name + '-pki', 'defaultMode': 0o440}},
                    {'name': 'config', 'configMap': {'name': name + '-config'}}]}
    # Install stopped; the first acceptance run controls link failures before seeding.
    return [pvc(name + '-state', NAMESPACE),
        {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': name + '-config', 'namespace': NAMESPACE},
         'data': {'kms.json': json.dumps(config(name))}},
        {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': name, 'namespace': NAMESPACE},
         'spec': {'selector': label, 'ports': [{'name': 'https', 'port': 8443, 'targetPort': 8443}]}},
        {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': name, 'namespace': NAMESPACE},
         'spec': {'replicas': 0, 'strategy': {'type': 'Recreate'}, 'selector': {'matchLabels': label},
                  'template': {'metadata': {'labels': label}, 'spec': pod}}},
        {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
         'metadata': {'name': name + '-ingress', 'namespace': NAMESPACE},
         'spec': {'podSelector': {'matchLabels': label}, 'policyTypes': ['Ingress'], 'ingress': [{
            'from': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'tfs'}},
                      'podSelector': {'matchExpressions': [{'key': 'app', 'operator': 'In', 'values': ['deviceservice', 'lux-client']}]}},
                     {'podSelector': {'matchExpressions': [{'key': 'app', 'operator': 'In',
                                                           'values': list(config(name)['inter_kms']['peers'])}]}}],
            'ports': [{'protocol': 'TCP', 'port': 8443}]}]}}]


def main():
    if socket.gethostname() != 'lima-transeuroogs-tfs':
        raise SystemExit('Run inside the dedicated TeraFlow VM.')
    lab.require_owned('tfs')
    DATA.mkdir(mode=0o700, exist_ok=True)
    if (DATA / 'installed').exists():
        raise SystemExit('Already installed; use status/start commands. State will not be reset or reseeded.')
    lab.namespace(NAMESPACE)
    pki = DATA / 'pki'
    if not pki.exists():
        lab.run([str(ROOT / 'bin/test-pki'), '--profile=luxembourg', '--out=' + str(pki)], capture=False)
    image = json.loads((ROOT / 'lab-state/kms-image.json').read_text())['image']
    for name in NODES:
        signing = DATA / (name + '.key.pem')
        if not signing.exists():
            lab.run([str(ROOT / 'bin/kms-metadata'), 'keygen', '--private', str(signing),
                     '--public', str(DATA / (name + '.pub.pem'))], capture=False)
        lab.apply([lab.secret(name + '-pki', NAMESPACE, {file: (pki / file).read_bytes()
                   for file in ('ca.crt.pem', name + '.crt.pem', name + '.key.pem')}),
                   lab.secret(name + '-signing', NAMESPACE, {'signing.key.pem': signing.read_bytes()})])
        lab.apply(endpoint(name, image))
    # The baseline LU controller mount remains intact.
    lab.apply([lab.secret('lux-management-mtls', 'tfs', {file: (pki / file).read_bytes()
               for file in ('ca.crt.pem', 'controller-sae.crt.pem', 'controller-sae.key.pem')})])
    existing = json.loads(lab.kube('-n', 'tfs', 'get', 'deployment', 'deviceservice', '-o', 'json'))
    server_name = existing['spec']['template']['spec']['containers'][0]['name']
    patch = {'spec': {'template': {'spec': {
        'volumes': [{'name': 'lux-management-mtls', 'secret': {'secretName': 'lux-management-mtls', 'defaultMode': 0o400}}],
        'containers': [{'name': server_name, 'volumeMounts': [{'name': 'lux-management-mtls',
            'mountPath': '/run/transeuroogs/lux-mtls', 'readOnly': True}]}]}}}}
    print(lab.kube('-n', 'tfs', 'patch', 'deployment', 'deviceservice', '--type=strategic', '--patch', json.dumps(patch)), end='')
    client_files = ['ca.crt.pem'] + [n + suffix for n in ('sae-windhof', 'sae-betzdorf', 'controller-sae', 'unknown-sae', 'windhof')
                                                  for suffix in ('.crt.pem', '.key.pem')]
    lab.apply([lab.secret('lux-test-clients', 'tfs', {file: (pki / file).read_bytes() for file in client_files}),
               pvc('lux-test-state', 'tfs')])
    image = json.loads((ROOT / 'lab-state/controller-images.json').read_text())['device']
    lab.apply([{'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': 'lux-client', 'namespace': 'tfs'},
        'spec': {'replicas': 1, 'strategy': {'type': 'Recreate'}, 'selector': {'matchLabels': {'app': 'lux-client'}},
            'template': {'metadata': {'labels': {'app': 'lux-client'}}, 'spec': {
                'automountServiceAccountToken': False,
                'containers': [{'name': 'client', 'image': image, 'command': ['python', '-c', 'import time; time.sleep(86400)'],
                    'resources': {'requests': {'cpu': '50m', 'memory': '64Mi'}, 'limits': {'cpu': '500m', 'memory': '256Mi'}},
                    'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
                    'volumeMounts': [{'name': 'clients', 'mountPath': '/run/lux-clients', 'readOnly': True},
                                    {'name': 'state', 'mountPath': '/state'}]}],
                'volumes': [{'name': 'clients', 'secret': {'secretName': 'lux-test-clients', 'defaultMode': 0o400}},
                            {'name': 'state', 'persistentVolumeClaim': {'claimName': 'lux-test-state'}}]}}}}])
    (DATA / 'installed').write_text('Synthetic endpoints installed stopped; start with acceptance.py\n')
    print('Installed four synthetic endpoints; hardware interfaces are not connected.')


if __name__ == '__main__':
    main()
