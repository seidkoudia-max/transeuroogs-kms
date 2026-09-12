#!/usr/bin/env python3
"""Run the one-batch synthetic relay acceptance inside the dedicated lab VM.

Successful steps are checkpointed. A delivery interrupted before its checkpoint
requires inspection of the private receipt; it is never automatically retried.
"""
import hashlib
import fcntl
import json
import os
from pathlib import Path
import socket

from deploy import DATA, lab
from lux_profile import NAMESPACE, NODES

CONTROLLERS = ('contextservice', 'deviceservice', 'pathcompservice', 'qkd-appservice',
               'serviceservice', 'nbiservice', 'webuiservice')
CHECKPOINT = DATA / 'acceptance.json'


def save(value):
    temporary = CHECKPOINT.with_suffix('.tmp')
    with open(temporary, 'w', opener=lambda p, flags: os.open(p, flags, 0o600)) as stream:
        json.dump(value, stream); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, CHECKPOINT)
    descriptor = os.open(DATA, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def acquire_lock():
    stream = open(DATA / 'acceptance.lock', 'a', opener=lambda p, flags: os.open(p, flags, 0o600))
    try:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        stream.close()
        raise RuntimeError('Another acceptance runner owns this lab') from None
    return stream


def wait(namespace, *names):
    for name in names:
        print(lab.kube('-n', namespace, 'rollout', 'status', 'deployment/' + name, '--timeout=180s'), end='', flush=True)


def scale(namespace, names, replicas):
    print(lab.kube('-n', namespace, 'scale', *['deployment/' + n for n in names],
                   '--replicas=' + str(replicas)), end='', flush=True)
    if replicas:
        wait(namespace, *names)
    else:
        for name in names:
            print(lab.kube('-n', namespace, 'wait', '--for=delete', 'pod', '-l', 'app=' + name,
                           '--timeout=120s'), end='', flush=True)


def restart(names):
    print(lab.kube('-n', NAMESPACE, 'rollout', 'restart', *['deployment/' + n for n in names]), end='', flush=True)
    wait(NAMESPACE, *names)


def check(action, label='policy'):
    # The client emits assertions and aggregate counts only, never key responses.
    lab.run(['sudo', 'microk8s', 'kubectl', '-n', 'tfs', 'exec', 'deployment/lux-client', '--',
             'python', '/opt/lux-test/check.py', action, '--label', label], capture=False)


def install_client():
    source = Path(__file__).resolve().parent
    files = {name: (source / name).read_text() for name in ('check.py', 'lux_profile.py', 'topology.json')}
    digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    lab.apply([{'apiVersion': 'v1', 'kind': 'ConfigMap',
                'metadata': {'name': 'lux-test-code', 'namespace': 'tfs'}, 'data': files}])
    patch = {'spec': {'template': {'metadata': {'annotations': {'lux-test-code': digest}}, 'spec': {
        'volumes': [{'name': 'test-code', 'configMap': {'name': 'lux-test-code'}}],
        'containers': [{'name': 'client', 'env': [{'name': 'PYTHONPATH', 'value': '/var/teraflow'}], 'volumeMounts': [
            {'name': 'test-code', 'mountPath': '/opt/lux-test', 'readOnly': True}]}]}}}}
    print(lab.kube('-n', 'tfs', 'patch', 'deployment', 'lux-client', '--type=strategic',
                   '--patch', json.dumps(patch)), end='', flush=True)
    wait('tfs', 'lux-client', 'deviceservice')


def steps():
    # Keep each state-changing delivery in a separate durable checkpoint.
    plan = [('start-first', lambda: scale(NAMESPACE, ('windhof', 'jfk-tq'), 1), False),
            ('first-link-blocked', lambda: check('blocked'), False),
            ('restart-origin-pending', lambda: restart(('windhof',)), False),
            ('first-link-still-blocked', lambda: check('blocked'), False),
            ('connect-jfk', lambda: scale(NAMESPACE, ('jfk-idq',), 1), False),
            ('jfk-pending', lambda: check('pending'), False),
            ('second-link-blocked', lambda: check('blocked'), False),
            ('restart-jfk-pending', lambda: restart(('jfk-idq', 'jfk-tq')), False),
            ('jfk-recovered-pending', lambda: check('pending'), False),
            ('second-link-still-blocked', lambda: check('blocked'), False),
            ('connect-betzdorf', lambda: scale(NAMESPACE, ('betzdorf',), 1), False),
            ('all-acknowledged', lambda: check('ready'), False),
            ('onboard', lambda: check('onboard'), False),
            ('authorization', lambda: check('isolation'), False)]
    for action in ('pause', 'master', 'deny', 'require-evidence', 'deny', 'resume', 'slave', 'replay'):
        plan.append(('policy-' + str(len(plan)) + '-' + action, lambda a=action: check(a), action in ('master', 'slave')))
    plan += [('outage-master', lambda: check('master', 'endpoint-outage'), True),
             ('origin-off', lambda: scale(NAMESPACE, ('windhof',), 0), False),
             ('outage-slave', lambda: check('slave', 'endpoint-outage'), True),
             ('outage-replay', lambda: check('replay', 'endpoint-outage'), False),
             ('origin-on', lambda: scale(NAMESPACE, ('windhof',), 1), False),
             ('restart-all', lambda: restart(tuple(NODES)), False),
             ('restart-replay', lambda: check('replay'), False),
             ('controller-off', lambda: scale('tfs', CONTROLLERS, 0), False),
             ('controller-off-master', lambda: check('master', 'controller-outage'), True),
             ('controller-off-slave', lambda: check('slave', 'controller-outage'), True),
             ('controller-off-replay', lambda: check('replay', 'controller-outage'), False),
             ('controller-on', lambda: scale('tfs', CONTROLLERS, 1), False),
             ('history', lambda: check('history'), False),
             ('state', lambda: check('state'), False),
             ('inventory', lambda: check('inventory'), False)]
    return plan


def remaining(progress, plan):
    completed = progress['completed']
    if completed != [name for name, _, _ in plan[:len(completed)]]:
        raise RuntimeError('Acceptance plan changed; inspect the checkpoint without resetting key state')
    pending = plan[len(completed):]
    if progress['active']:
        if not pending or progress['active'] != pending[0][0]:
            raise RuntimeError('Invalid active checkpoint; inspect it without resetting key state')
        if pending[0][2]:
            raise RuntimeError('Interrupted delivery: inspect its private receipt before manual checkpoint recovery')
    return pending


def main():
    if socket.gethostname() != 'lima-transeuroogs-tfs':
        raise RuntimeError('Run inside the dedicated TeraFlow VM')
    for namespace in ('tfs', NAMESPACE):
        lab.require_owned(namespace)
    if not (DATA / 'installed').exists():
        raise RuntimeError('Install the synthetic endpoints first')
    with acquire_lock():
        run_acceptance()


def run_acceptance():
    progress = json.loads(CHECKPOINT.read_text()) if CHECKPOINT.exists() else {'completed': [], 'active': None}
    plan = steps()
    pending = remaining(progress, plan)
    if not pending:
        print('Acceptance already completed; keys will not be reseeded or redelivered.')
        return
    install_client()
    try:
        # A previous failed run restores the controller; re-establish this test's outage on resume.
        completed = progress['completed']
        if 'controller-off' in completed and 'controller-on' not in completed:
            scale('tfs', CONTROLLERS, 0)
        for name, operation, _ in pending:
            progress['active'] = name; save(progress)
            print('BEGIN ' + name, flush=True)
            operation()
            progress['completed'].append(name); progress['active'] = None; save(progress)
            print('PASS ' + name, flush=True)
    finally:
        scale('tfs', CONTROLLERS, 1)
        # Leave the web UI available after intentional controller outages.
        lab.run(['sudo', 'systemctl', 'restart', 'transeuroogs-webui'], capture=False)
    print('PASS Luxembourg synthetic two-link acceptance; no QKD hardware connected.', flush=True)


if __name__ == '__main__':
    main()
