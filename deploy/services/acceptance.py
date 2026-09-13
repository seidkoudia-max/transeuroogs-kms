#!/usr/bin/env python3
"""Checkpointed synthetic TeraFlow acceptance; retain all KMS journals on failure."""
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from deploy import STATE, NAMESPACE, LABELS, owned, kube
from service_profile import NODES

CONTROLLERS = ('contextservice', 'deviceservice', 'pathcompservice', 'qkd-appservice',
               'serviceservice', 'nbiservice', 'webuiservice')
CHECKPOINT = STATE / 'acceptance.json'


def save(value):
    temporary = CHECKPOINT.with_suffix('.tmp')
    with open(temporary, 'w', opener=lambda p, f: os.open(p, f, 0o600)) as stream:
        json.dump(value, stream); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, CHECKPOINT)
    descriptor = os.open(STATE, os.O_RDONLY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def check(action, label='normal'):
    result = kube('-n', 'tfs', 'exec', 'deployment/services-test', '--', 'python',
                  '/opt/transeuroogs-services/runtime.py', action, '--label', label)
    print(result, end='', flush=True)


def wait(namespace, *names):
    for name in names:
        print(kube('-n', namespace, 'rollout', 'status', 'deployment/' + name, '--timeout=60s'), end='', flush=True)


def restart(namespace, *names):
    print(kube('-n', namespace, 'rollout', 'restart', *['deployment/' + n for n in names]), end='', flush=True)
    wait(namespace, *names)


def scale(name, replicas):
    print(kube('-n', 'tfs', 'scale', 'deployment/' + name, '--replicas=' + str(replicas)), end='', flush=True)
    if replicas: wait('tfs', name)
    else: print(kube('-n', 'tfs', 'wait', '--for=delete', 'pod', '-l', 'app=' + name, '--timeout=60s'), end='', flush=True)


def outage():
    # Save original replica counts before the first disruption. On any exit,
    # including a later invocation after a crash, restore these exact counts.
    progress = json.loads(CHECKPOINT.read_text())
    if 'restore' not in progress:
        progress['restore'] = {n: json.loads(kube('-n', 'tfs', 'get', 'deployment', n, '-o', 'json'))['spec']['replicas'] for n in CONTROLLERS}
        save(progress)
    try:
        # Refresh the finite telemetry lease before stopping the controller.
        check('observe')
        for name in reversed(CONTROLLERS): scale(name, 0)
        check('delivery', 'controller-outage')
        check('replay', 'controller-outage')
    finally:
        restore()


def restore():
    progress = json.loads(CHECKPOINT.read_text())
    for name, replicas in progress.get('restore', {}).items(): scale(name, replicas)
    if 'restore' in progress:
        subprocess.run(['sudo', 'systemctl', 'restart', 'transeuroogs-webui'], check=True)
        del progress['restore']; save(progress)


def steps():
    return [
        ('bootstrap', lambda: check('bootstrap')),
        ('lost-activation-reply', lambda: check('fault-activate')),
        ('restart-kms-and-providers', lambda: restart(NAMESPACE, *NODES, 'link-idq', 'link-tq')),
        ('restart-controller-and-worker', lambda: restart('tfs', 'deviceservice', 'services-test')),
        ('recover-exact-activation', lambda: check('activate')),
        ('fresh-telemetry', lambda: check('observe')),
        ('protected-relay-ready', recover_transfers),
        ('authorization', lambda: check('isolation')),
        ('matching-key-delivery', lambda: check('delivery')),
        ('prepare-undelivered-incident-keys', lambda: check('prepare-held')),
        ('incident-hold', lambda: check('hold')),
        ('hold-blocks-undelivered-keys', lambda: check('held')),
        ('restart-held-target', lambda: restart(NAMESPACE, 'betzdorf')),
        ('hold-survives-restart', lambda: check('held')),
        ('incident-release', lambda: check('release')),
        ('released-key-delivery', lambda: check('delivery', 'incident')),
        ('controller-outage-delivery', outage),
        ('recipient-replay-after-restart', lambda: check('replay')),
        ('signed-history-export', lambda: check('history')),
        ('controller-observed-state', lambda: check('state')),
    ]


def recover_transfers():
    check('retire-interrupted')
    check('ready')


def remaining(progress, plan):
    if progress['completed'] != [name for name, _ in plan[:len(progress['completed'])]]:
        raise RuntimeError('Acceptance plan changed; inspect checkpoints without resetting keys')
    pending = plan[len(progress['completed']):]
    if progress['active'] and (not pending or progress['active'] != pending[0][0]):
        raise RuntimeError('Invalid active acceptance checkpoint')
    # Delivery scripts themselves retain both request intents and fail closed on
    # any uncertain result. Exact completed deliveries are safe no-ops on resume.
    return pending


def main():
    if socket.gethostname() != 'lima-transeuroogs-tfs': raise RuntimeError('Dedicated VM required')
    if not owned(NAMESPACE, LABELS) or not owned('tfs', {'transeuroogs.lab': 'true'}): raise RuntimeError('Owned lab required')
    with open(STATE / 'acceptance.lock', 'a', opener=lambda p, f: os.open(p, f, 0o600)) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if CHECKPOINT.exists(): restore()
        else: save({'completed': [], 'active': None, 'started_at': time.time()})
        progress = json.loads(CHECKPOINT.read_text())
        for name, action in remaining(progress, steps()):
            progress['active'] = name; save(progress); print('BEGIN ' + name, flush=True)
            action()
            progress = json.loads(CHECKPOINT.read_text())
            progress['completed'].append(name); progress['active'] = None; save(progress)
            print('PASS ' + name, flush=True)
        progress['finished_at'] = time.time(); save(progress)
        print('PASS synthetic TeraFlow service acceptance; no QKD hardware connected.', flush=True)


if __name__ == '__main__': main()
