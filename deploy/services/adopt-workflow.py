#!/usr/bin/env python3
"""Copy the completed material-free lab workflow into the operator's own PVC."""
import json
import socket
from deploy import STATE, NAMESPACE, LABELS, owned, kube
from service_profile import NODES


def validate(files):
    expected = {'desired.json', 'workflow.json'} | {'link-' + n + '.json' for n in NODES}
    if set(files) != expected or len(json.dumps(files)) > 2 << 20: raise RuntimeError('Unexpected workflow files')
    job = files['workflow.json']
    if job['status'] != 'complete' or job['completed'] != len(job['actions']) or job['desired'] != files['desired.json']:
        raise RuntimeError('Only a completed, consistent workflow can be adopted')


def main():
    if socket.gethostname() != 'lima-transeuroogs-tfs' or not owned(NAMESPACE, LABELS): raise RuntimeError('Owned lab required')
    progress = json.loads((STATE / 'acceptance.json').read_text())
    if progress['active'] is not None or 'controller-observed-state' not in progress['completed']: raise RuntimeError('Complete acceptance first')
    names = ['desired.json', 'workflow.json'] + ['link-' + n + '.json' for n in NODES]
    files = {n: json.loads(kube('-n', 'tfs', 'exec', 'deployment/services-test', '--', 'cat', '/state/private/' + n)) for n in names}
    validate(files)
    code = '''import json,sys
sys.path.insert(0, '/opt/transeuroogs-services')
from runtime import DATA, save
files=json.load(sys.stdin)
for name,value in files.items():
    path=DATA/name
    if path.exists() and json.loads(path.read_text()) != value: raise RuntimeError('Operator owns a different intent; no overwrite')
for name,value in files.items():
    path=DATA/name
    if not path.exists(): save(path,value)
'''
    kube('-n', 'tfs', 'exec', '-i', 'deployment/services-operator', '--', 'python', '-c', code, data=json.dumps(files))
    print(kube('-n', 'tfs', 'exec', 'deployment/services-operator', '--', 'python', '/opt/transeuroogs-services/runtime.py', 'activate'), end='')
    print('Operator adopted the completed workflow; no key-plane credentials copied.')


if __name__ == '__main__': main()
