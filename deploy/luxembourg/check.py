#!/usr/bin/env python3
"""In-pod acceptance client. Output contains neither keys nor key fingerprints."""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import ssl
import sys
import time
import uuid

from common.proto.context_pb2 import Context, TopologyId
from context.client.ContextClient import ContextClient
from device.service.drivers.transeuroogs.client import Client, ManagementError
from lux_profile import NAMESPACE, NODES, PAIR, TOPOLOGY, host, identity

PKI = Path('/run/lux-clients')
RECEIPTS = Path('/state/private')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def manager(name, actor='controller-sae'):
    return Client(host(name), 8443, ca_file=str(PKI / 'ca.crt.pem'),
        cert_file=str(PKI / (actor + '.crt.pem')), key_file=str(PKI / (actor + '.key.pem')),
        server_identity=identity(name), timeout=10)


def request(name, actor, method, path, body=None):
    context = ssl.create_default_context(cafile=str(PKI / 'ca.crt.pem'))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(PKI / (actor + '.crt.pem'), PKI / (actor + '.key.pem'))
    connection = http.client.HTTPSConnection(host(name), 8443, context=context, timeout=10)
    try:
        connection.connect()
        uris = [v for k, v in connection.sock.getpeercert().get('subjectAltName', ()) if k == 'URI']
        require(uris == [identity(name)], 'Wrong endpoint URI')
        connection.request(method, path, body=None if body is None else json.dumps(body),
                           headers={'Content-Type': 'application/json'})
        response = connection.getresponse()
        raw = response.read(1 << 20)
        return response.status, json.loads(raw) if raw else None
    finally:
        connection.close()


def nbi(method, path, body=None):
    connection = http.client.HTTPConnection('nbiservice', 8080, timeout=90)
    try:
        connection.request(method, '/tfs-api' + path, body=None if body is None else json.dumps(body),
                           headers={'Content-Type': 'application/json'})
        response = connection.getresponse()
        require(200 <= response.status < 300, 'TeraFlow NBI rejected request')
        return json.loads(response.read())
    finally:
        connection.close()


def onboard():
    client = ContextClient()
    client.SetContext(Context(context_id={'context_uuid': {'uuid': 'admin'}}, name='admin'))
    for name, node in NODES.items():
        settings = {'profile': 'transeuroogs-allocation-v1', 'ca_file': '/run/transeuroogs/lux-mtls/ca.crt.pem',
            'cert_file': '/run/transeuroogs/lux-mtls/controller-sae.crt.pem',
            'key_file': '/run/transeuroogs/lux-mtls/controller-sae.key.pem', 'server_identity': identity(name), 'timeout': 10}
        rules = [{'action': 'CONFIGACTION_SET', 'custom': {'resource_key': '_connect/' + key, 'resource_value': value}}
                 for key, value in [('address', host(name)), ('port', '8443'), ('settings', json.dumps(settings))]]
        nbi('POST', '/devices', {'devices': [{'device_id': {'device_uuid': {'uuid': node['node_id']}},
            'name': node['label'] + ' [synthetic]', 'device_type': 'qkd-node',
            'device_drivers': ['DEVICEDRIVER_QKD'], 'device_config': {'config_rules': rules}}]})
        found = nbi('GET', '/device/' + node['node_id'])
        require(any('__node__' in r.get('custom', {}).get('resource_key', '')
                    for r in found['device_config']['config_rules']), 'Device discovery absent')
    inventory()


def inventory():
    # Device.AddDevice attaches nodes to the pinned controller's admin topology.
    topology = ContextClient().GetTopology(TopologyId(context_id={'context_uuid': {'uuid': 'admin'}},
                                                     topology_uuid={'uuid': 'admin'}))
    members = {item.device_uuid.uuid for item in topology.device_ids}
    require({node['node_id'] for node in NODES.values()} <= members, 'Lab nodes missing from the UI topology')
    for node in NODES.values():
        found = nbi('GET', '/device/' + node['node_id'])
        require(found['name'] == node['label'] + ' [synthetic]', 'Persisted device inventory mismatch')


def policy(name, **changes):
    before = {node: manager(node).state()['revision'] for node in NODES}
    state = manager(name).state()
    command = {'command_id': str(uuid.uuid4()), 'expected_revision': state['revision'], 'association': PAIR,
               'rule': dict(state['applications'][0]['rule'], **changes)}
    body = {'device_id': {'device_uuid': {'uuid': NODES[name]['node_id']}}, 'device_config': {'config_rules': [
        {'action': 'CONFIGACTION_SET', 'custom': {'resource_key': '/transeuroogs/allocation', 'resource_value': json.dumps(command)}}]}}
    for _ in range(2):
        nbi('PUT', '/device/' + NODES[name]['node_id'], body)
    for node in NODES:
        require(manager(node).state()['revision'] == before[node] + int(node == name), 'Policy replay or node isolation failed')


def blocked():
    code, status = request('windhof', 'sae-windhof', 'GET', '/api/v1/keys/SAE-BETZDORF/status')
    require(code == 200 and status['stored_key_count'] == 0, 'Keys became ready before destination acknowledgement')
    code, _ = request('windhof', 'sae-windhof', 'POST', '/api/v1/keys/SAE-BETZDORF/enc_keys', {'number': 1, 'size': 256})
    require(code == 503, 'Broken path released a key')


def ready(count):
    deadline = time.monotonic() + 50
    while time.monotonic() < deadline:
        code, status = request('windhof', 'sae-windhof', 'GET', '/api/v1/keys/SAE-BETZDORF/status')
        if code == 200 and status['stored_key_count'] == count:
            return
        time.sleep(0.25)
    raise RuntimeError('End-to-end acknowledgements did not complete')


def persist(path, value):
    RECEIPTS.mkdir(mode=0o700, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    with open(temporary, 'w', opener=lambda p, flags: os.open(p, flags, 0o600)) as stream:
        json.dump(value, stream); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(RECEIPTS, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def master(label):
    path = RECEIPTS / (label + '.json')
    require(not path.exists(), 'Test receipt already exists; do not retry an uncertain delivery')
    persist(path, {'state': 'master-intent'})
    code, data = request('windhof', 'sae-windhof', 'POST', '/api/v1/keys/SAE-BETZDORF/enc_keys', {'number': 2, 'size': 256})
    require(code == 200 and len(data['keys']) == 2, 'Master delivery failed')
    values = []
    for key in data['keys']:
        raw = base64.b64decode(key['key'], validate=True)
        require(len(raw) == 32 and uuid.UUID(key['key_ID']).version == 4, 'Wrong key profile')
        values.append({'key_ID': key['key_ID'], 'digest': hashlib.sha256(raw).hexdigest()})
    require(len({v['key_ID'] for v in values}) == 2, 'Duplicate IDs')
    persist(path, {'state': 'master-received', 'keys': values})


def slave(label, deny=False, replay=False):
    path = RECEIPTS / (label + '.json')
    receipt = json.loads(path.read_text())
    require(receipt['state'] == ('delivered' if replay else 'master-received'), 'Uncertain or incorrect receipt phase')
    ids = [{'key_ID': value['key_ID']} for value in receipt['keys']]
    if not deny and not replay:
        persist(path, dict(receipt, state='slave-intent'))
    code, data = request('betzdorf', 'sae-betzdorf', 'POST', '/api/v1/keys/SAE-WINDHOF/dec_keys', {'key_IDs': ids})
    if deny or replay:
        require(code == 503, 'Denied or duplicate delivery succeeded')
        return
    require(code == 200 and len(data['keys']) == len(ids), 'Slave delivery failed')
    for expected, actual in zip(receipt['keys'], data['keys']):
        digest = hashlib.sha256(base64.b64decode(actual['key'], validate=True)).hexdigest()
        require(actual['key_ID'] == expected['key_ID'] and secrets.compare_digest(digest, expected['digest']), 'End-to-end keys differ')
    persist(path, dict(receipt, state='delivered'))


def isolation():
    for name in NODES:
        for actor in ('sae-windhof', 'unknown-sae'):
            try:
                manager(name, actor).state()
            except ManagementError:
                pass
            else:
                raise RuntimeError('Non-controller accessed management')
        code, _ = request(name, 'controller-sae', 'GET', '/api/v1/keys/SAE-BETZDORF/status')
        require(code == 401, 'Controller accessed the key plane')
    for name in ('jfk-idq', 'jfk-tq'):
        for actor in ('sae-windhof', 'sae-betzdorf'):
            code, _ = request(name, actor, 'GET', '/api/v1/keys/SAE-BETZDORF/status')
            require(code == 401, 'Trusted relay exposed local SAE access')
    for actor in ('sae-windhof', 'controller-sae', 'windhof'):
        code, _ = request('jfk-tq', actor, 'POST', '/kmapi/v1/ext_keys', {})
        require(code == 401, 'Unauthorized identity crossed JFK interworking boundary')


def records(name):
    after, watermark, latest, controls = 0, None, {}, 0
    while True:
        path = '/metadata/v1/events?after=' + str(after)
        if watermark is not None:
            path += '&through=' + str(watermark)
        code, data = request(name, 'unknown-sae', 'GET', path)
        require(code == 200, 'Investigator history unavailable')
        page = data['page']; watermark = page['watermark']
        for item in page['events']:
            event = item['event']
            controls += int('control' in event)
            if 'record' in event:
                latest[event['record']['key']['key_id']] = event['record']
        if page['page_complete']:
            return latest, controls
        require(page['next'] > after, 'History did not advance')
        after = page['next']


def pending():
    deadline = time.monotonic() + 50
    while time.monotonic() < deadline:
        latest, _ = records('jfk-tq')
        if latest and all(r['holding_material'] and not r['ready'] for r in latest.values()):
            return
        time.sleep(0.5)
    raise RuntimeError('No pending relay material at JFK on the second link')


def history():
    all_ids = []
    for name in NODES:
        latest, controls = records(name)
        require(len(latest) == 64, 'Missing or duplicated relayed key history')
        require(controls == manager(name).state()['revision'], 'Policy history mismatch')
        if name in ('jfk-idq', 'jfk-tq'):
            require(all(r['role'] == 'relay' and not r['holding_material'] for r in latest.values()), 'JFK retained acknowledged key material')
        all_ids.append(set(latest))
    require(all(ids == all_ids[0] for ids in all_ids), 'Key IDs changed across vendor-domain handoff')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('blocked', 'ready', 'pending', 'onboard', 'inventory', 'isolation', 'history',
        'master', 'slave', 'deny', 'replay', 'pause', 'require-evidence', 'resume', 'state'))
    parser.add_argument('--label', choices=('policy', 'endpoint-outage', 'controller-outage'), default='policy')
    args = parser.parse_args()
    if args.action == 'blocked': blocked()
    elif args.action == 'ready': ready(64)
    elif args.action == 'pending': pending()
    elif args.action == 'onboard': onboard()
    elif args.action == 'inventory': inventory()
    elif args.action == 'isolation': isolation()
    elif args.action == 'history': history()
    elif args.action == 'master': master(args.label)
    elif args.action in ('slave', 'deny', 'replay'): slave(args.label, deny=args.action == 'deny', replay=args.action == 'replay')
    elif args.action == 'pause': policy('betzdorf', paused=True)
    elif args.action == 'require-evidence': policy('betzdorf', paused=False, require_evidence=True)
    elif args.action == 'resume': policy('betzdorf', paused=False, require_evidence=False)
    elif args.action == 'state':
        print(json.dumps({name: {'revision': (s := manager(name).state())['revision'],
                                'counts': s['applications'][0]['counts']} for name in NODES}))
    print(json.dumps({'result': 'PASS', 'action': args.action, 'label': args.label,
                      'profile': TOPOLOGY['profile'], 'hardware_connected': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        detail = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print('Luxembourg acceptance failed: ' + detail, file=sys.stderr)
        sys.exit(1)
