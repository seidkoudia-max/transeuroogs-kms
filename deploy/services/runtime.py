#!/usr/bin/env python3
"""Run the controller-integrated workflow, read-only monitor and synthetic tests."""
import argparse
import copy
from datetime import datetime
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import sys
import threading
import time
import uuid
import grpc

sys.path.insert(0, '/var/teraflow')
from common.proto.context_pb2 import Device, DeviceId, Link, Service
from context.client.ContextClient import ContextClient
from device.client.DeviceClient import DeviceClient
from device.service.drivers.transeuroogs.client import Client, ManagementError
from device.service.drivers.transeuroogs.controller import ControllerAdapter, NBI
from device.service.drivers.transeuroogs.orchestrator import Orchestrator, Incomplete
from device.service.drivers.transeuroogs.adapter import SyntheticAdapter
from device.service.drivers.transeuroogs.QKDDriver import ALLOCATION, STATE
from service_profile import NODES, NAMESPACE, TOPOLOGY, PAIR, ACTOR, config, host, identity

DATA = Path('/state/private')
PKI = Path('/run/services')


def require(value, message):
    if not value: raise RuntimeError(message)


def save(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    with open(temporary, 'w', opener=lambda p, f: os.open(p, f, 0o600)) as stream:
        json.dump(value, stream, allow_nan=False); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def manager(name, role='observer-sae'):
    return Client(host(name), 8443, ca_file=str(PKI / 'ca.crt.pem'), cert_file=str(PKI / (role + '.crt.pem')),
                  key_file=str(PKI / (role + '.key.pem')), server_identity=identity(name), timeout=10)


def fresh(node_id):
    value = DeviceClient().stub.GetInitialConfig(DeviceId(device_uuid={'uuid': node_id}), timeout=20)
    for rule in value.config_rules:
        if rule.WhichOneof('config_rule') == 'custom' and rule.custom.resource_key == STATE:
            return json.loads(rule.custom.resource_value)
    raise RuntimeError('Controller did not return fresh KMS state')


def drivers():
    return {name: ControllerAdapter(n['node_id'], manager(name), fresh, actor=ACTOR) for name, n in NODES.items()}


def endpoint(name):
    return {'device_id': {'device_uuid': {'uuid': NODES[name]['node_id']}}, 'endpoint_uuid': {'uuid': 'qkd-1'},
            'topology_id': {'context_id': {'context_uuid': {'uuid': 'admin'}}, 'topology_uuid': {'uuid': 'admin'}}}


def onboard():
    nbi = NBI()
    for name, node in NODES.items():
        settings = {'profile': 'transeuroogs-allocation-v1', 'ca_file': '/run/transeuroogs/services/ca.crt.pem',
                    'cert_file': '/run/transeuroogs/services/controller-sae.crt.pem', 'key_file': '/run/transeuroogs/services/controller-sae.key.pem',
                    'server_identity': identity(name), 'timeout': 10}
        item = {'device_id': {'device_uuid': {'uuid': node['node_id']}}, 'name': node['label'] + ' [services synthetic]',
                'device_type': 'qkd-node', 'device_drivers': ['DEVICEDRIVER_QKD'], 'device_config': {'config_rules': [
                    {'action': 'CONFIGACTION_SET', 'custom': {'resource_key': '_connect/' + key, 'resource_value': value}}
                    for key, value in [('address', host(name)), ('port', '8443'), ('settings', json.dumps(settings))]]}}
        # The pinned NBI turns a missing Context device into HTTP 500. Use the
        # typed Context read to distinguish absence from a controller failure.
        try: ContextClient().stub.GetDevice(DeviceId(device_uuid={'uuid': node['node_id']}), timeout=20)
        except grpc.RpcError as error:
            if error.code() != grpc.StatusCode.NOT_FOUND: raise
            nbi.request('POST', '/devices', {'devices': [item]})
        existing = nbi.request('GET', '/device/' + node['node_id'])
        require(existing['name'] == item['name'], 'Conflicting controller inventory identity')
        require(len(existing.get('device_endpoints', [])) == 1, 'Configured QKD interface not discovered')
        require(fresh(node['node_id'])['node_id'] == node['node_id'], 'Fresh Device RPC failed')
    for link in TOPOLOGY['links']:
        ContextClient().SetLink(Link(link_id={'link_uuid': {'uuid': link['link_id']}}, name=link['vendor'] + ' [synthetic protected link]',
                                     link_endpoint_ids=[endpoint(link['source']), endpoint(link['target'])]))


def link_intents():
    for name, driver in drivers().items():
        path = DATA / ('link-' + name + '.json')
        if path.exists(): command = json.loads(path.read_text())
        else:
            state = manager(name).state(); link = state['links'][0]
            require(not link['state']['present'], 'Existing link requires recovery of original intent')
            command = {'command_id': str(uuid.uuid4()), 'expected_revision': state['revision'], 'association': PAIR,
                       'service': {'operation': 'link_create', 'resource_id': link['catalog']['link_id'], 'enabled': True}}
            save(path, command)
        require(driver.SetConfig([(ALLOCATION, command)]) == [True], 'Controller link command unresolved')


def observations():
    for name in NODES:
        client = manager(name, 'adapter-sae'); state = client.state()
        SyntheticAdapter(client).observe(state['links'][0]['catalog']['link_id'])


def activate(fault=False):
    intent = DATA / 'desired.json'
    if intent.exists(): desired = json.loads(intent.read_text())
    else:
        desired = {}
        for name in NODES:
            state = manager(name).state(); app = state['applications'][0]
            desired[name] = {'node_id': state['node_id'], 'pool': app['pool'], 'association': PAIR,
                             'rule': config(name)['sdn']['applications'][0]['rule'],
                             'service': {'operation': 'application_create', 'resource_id': app['app_id'], 'ttl': 86400,
                                         'backing_links': [state['links'][0]['catalog']['link_id']]}}
        save(intent, desired)
    current = drivers()
    if fault:
        base = current['betzdorf']
        class Lose:
            def GetConfig(self, keys): return base.GetConfig(keys)
            def SetConfig(self, resources):
                result = base.SetConfig(resources)
                if result == [True] and resources[0][1].get('rule', {}).get('paused') is False:
                    save(DATA / 'lost-response.json', {'command_id': resources[0][1]['command_id'], 'committed_revision': resources[0][1]['expected_revision'] + 1})
                    return [ManagementError()]
                return result
        current['betzdorf'] = Lose()
    job = Orchestrator(current, DATA / 'workflow.json')
    try: out = job.run(desired)
    except Incomplete:
        if not fault: raise
        out = json.loads((DATA / 'workflow.json').read_text())
        require(out['status'] == 'partial_activation', 'Fault occurred before actual activation')
    else:
        require(not fault, 'Lost activation was not reported')
    return out['status']


def request(name, role, method, path, body=None):
    tc = ssl.create_default_context(cafile=str(PKI / 'ca.crt.pem')); tc.minimum_version = ssl.TLSVersion.TLSv1_3
    tc.load_cert_chain(str(PKI / (role + '.crt.pem')), str(PKI / (role + '.key.pem')))
    conn = http.client.HTTPSConnection(host(name), 8443, context=tc, timeout=10)
    try:
        conn.connect()
        require([v for k, v in conn.sock.getpeercert().get('subjectAltName', ()) if k == 'URI'] == [identity(name)], 'KMS URI pin mismatch')
        conn.request(method, path, body=None if body is None else json.dumps(body), headers={'Content-Type': 'application/json'})
        response = conn.getresponse(); raw = response.read(1048577)
        require(len(raw) <= 1048576, 'Oversized response')
        return response.status, json.loads(raw) if raw else {}
    finally: conn.close()


def prepare_delivery(label):
    path = DATA / ('delivery-' + label + '.json')
    if path.exists():
        require(json.loads(path.read_text())['status'] in ('master_delivered', 'confirmed'), 'Uncertain delivery requires investigation; no automatic retry')
        return
    save(path, {'status': 'intent'})
    code, first = request('windhof', 'sae-windhof', 'POST', '/api/v1/keys/SAE-BETZDORF/enc_keys', {'number': 2, 'size': 256})
    require(code == 200, 'Source delivery failed; intent retained')
    ids = [{'key_ID': k['key_ID']} for k in first['keys']]
    receipt = {'status': 'master_delivered', 'ids': ids, 'digest': hashlib.sha256(json.dumps(first, sort_keys=True).encode()).hexdigest()}
    save(path, receipt)


def delivery(label):
    prepare_delivery(label)
    path = DATA / ('delivery-' + label + '.json'); receipt = json.loads(path.read_text())
    if receipt['status'] == 'confirmed': return
    # Persist recipient intent before the request too: a dropped successful
    # response must never cause an automatic second delivery attempt.
    receipt['status'] = 'recipient_intent'; save(path, receipt)
    code, second = request('betzdorf', 'sae-betzdorf', 'POST', '/api/v1/keys/SAE-WINDHOF/dec_keys', {'key_IDs': receipt['ids']})
    require(code == 200 and hashlib.sha256(json.dumps(second, sort_keys=True).encode()).hexdigest() == receipt['digest'], 'Remote delivery mismatch; known IDs remain burned')
    receipt['status'] = 'confirmed'; save(path, receipt)
    replay(label)


def replay(label):
    receipt = json.loads((DATA / ('delivery-' + label + '.json')).read_text())
    code, _ = request('betzdorf', 'sae-betzdorf', 'POST', '/api/v1/keys/SAE-WINDHOF/dec_keys', {'key_IDs': receipt['ids']})
    require(code == 503, 'Recipient replay accepted')


def protection(operation):
    path = DATA / ('protection-' + operation + '.json')
    if path.exists(): command = json.loads(path.read_text())
    else:
        code, state = request('betzdorf', 'protection-sae', 'GET', '/federation/v1/state')
        require(code == 200, 'Protection state unavailable')
        incident = str(uuid.uuid4()) if operation == 'hold' else json.loads((DATA / 'protection-hold.json').read_text())['incident_id']
        command = {'action_id': str(uuid.uuid4()), 'incident_id': incident, 'pool_id': config('betzdorf')['federation']['pools'][0]['binding']['pool_id'],
                   'expected_revision': state['revision'], 'operation': operation, 'reason': 'synthetic integrated acceptance'}
        save(path, command)
    code, result = request('betzdorf', 'protection-sae', 'POST', '/federation/v1/actions', command)
    require(code == 200, 'Protection operation failed')
    return result


def status():
    nodes = {name: fresh(node['node_id']) for name, node in NODES.items()}
    active = all(service_enabled(s['applications'][0]) for s in nodes.values())
    return {'profile': TOPOLOGY['profile'], 'observed_at': time.time(), 'controller': 'TeraFlow v7 NBI + Device',
            'hardware_connected': False, 'delivery_enabled': active, 'nodes': nodes,
            'pending': ['SES and vendor interface acceptance', 'ETSI 021/023 models', 'production PKI/HSM/HA', 'standard QoS and event transport']}


def service_enabled(app):
    service = app['service']
    expiry = service.get('expires_at')
    return (not app['rule']['paused'] and service['registered'] and not app.get('protection_gate')
            and (expiry is None or datetime.fromisoformat(expiry.replace('Z', '+00:00')).timestamp() > time.time()))


def records(name):
    after, watermark, latest, controls, pages = 0, None, {}, 0, []
    for _ in range(1024):
        path = '/metadata/v1/events?after=' + str(after)
        if watermark is not None: path += '&through=' + str(watermark)
        code, data = request(name, 'unknown-sae', 'GET', path)
        require(code == 200, 'Investigator history unavailable')
        page = data['page']; watermark = page['watermark']; pages.append(data)
        for item in page['events']:
            event = item['event']; controls += int('control' in event)
            if 'record' in event: latest[event['record']['key']['key_id']] = event['record']
        if page['page_complete']: return latest, pages, controls
        require(page['next'] > after, 'History did not advance'); after = page['next']
    raise RuntimeError('History exceeds bounded export')


def recovery_plan(source, target):
    require(len(source) == 64, 'Unexpected source batch; refuse automatic recovery')
    healthy = {k for k, r in source.items() if r.get('ready') and not r.get('voiding')}
    require(healthy == {k for k, r in target.items() if r.get('ready') and not r.get('voiding')}, 'Ready sets differ; wait for acknowledgements')
    require(len(healthy) >= 32, 'Too few successful transfers for acceptance')
    pending = set(source) - healthy
    for k in pending:
        r = source[k]
        require(r.get('transfer_intent') and not r.get('ready') and r.get('master_state') == 'RESERVED', 'Refuse retirement of a ready, delivered or terminal key')
    return {'healthy_ids': sorted(healthy), 'retire_ids': sorted(pending), 'synthetic_restart_recovery': True}


def retire_interrupted():
    path = DATA / 'recovery.json'
    if path.exists(): plan = json.loads(path.read_text())
    else:
        # Allow in-flight acknowledgements to settle, then explicitly retire the
        # remaining synthetic test intents. Never retry a consuming 014 intake.
        deadline = time.monotonic() + 50
        while time.monotonic() < deadline:
            counts = [manager(n).state()['applications'][0]['counts']['eligible'] for n in ('windhof', 'betzdorf')]
            if counts == [64, 64]: break
            time.sleep(1)
        plan = recovery_plan(records('windhof')[0], records('betzdorf')[0]); save(path, plan)
    if plan['retire_ids']:
        for name, peer in [('jfk-idq', 'windhof'), ('windhof', 'jfk-idq')]:
            body = {'key_ids': plan['retire_ids'], 'initiator_sae_id': PAIR['master'], 'target_sae_ids': [PAIR['slave']],
                    'ack_callback_url': 'https://' + host(peer) + ':8443/qkd/v1/ext_keys/ack'}
            code, _ = request(name, peer, 'POST', '/qkd/v1/ext_keys/void', body)
            require(code == 202, 'Explicit synthetic transfer retirement failed')
    print(json.dumps({'synthetic_transfers_ready': len(plan['healthy_ids']), 'explicitly_retired': len(plan['retire_ids'])}), flush=True)


def history():
    plan = json.loads((DATA / 'recovery.json').read_text())
    healthy, retired = set(plan['healthy_ids']), set(plan['retire_ids'])
    pages, counts = [], {}
    for name in NODES:
        latest, node_pages, controls = records(name); pages.extend(node_pages)
        require(healthy <= set(latest) <= healthy | retired, 'Missing or foreign key history')
        require(all(r.get('voiding') and not r['holding_material'] for k, r in latest.items() if k in retired), 'Retired material remains usable')
        require(controls == manager(name).state()['revision'], 'Signed control history mismatch')
        if name in ('jfk-idq', 'jfk-tq'):
            require(all(r['role'] == 'relay' and not r['holding_material'] for r in latest.values()), 'JFK retained acknowledged key material')
        counts[name] = {'keys': len(latest), 'controls': controls, 'watermark': node_pages[0]['page']['watermark']}
    if retired:
        code, _ = request('betzdorf', 'sae-betzdorf', 'POST', '/api/v1/keys/SAE-WINDHOF/dec_keys', {'key_IDs': [{'key_ID': k} for k in sorted(retired)]})
        require(code == 503, 'Retired key delivered')
    save(DATA / 'signed-pages.json', pages)
    save(DATA / 'history-summary.json', counts)


def publish(value):
    context = ContextClient()
    for name, state in value['nodes'].items():
        device = context.GetDevice(DeviceId(device_uuid={'uuid': NODES[name]['node_id']}))
        for rule in device.device_config.config_rules:
            if rule.WhichOneof('config_rule') == 'custom' and rule.custom.resource_key == STATE:
                rule.custom.resource_value = json.dumps(state)
                break
        else:
            rule = device.device_config.config_rules.add(action=1)
            rule.custom.resource_key = STATE; rule.custom.resource_value = json.dumps(state)
        context.SetDevice(device)
    context.SetService(Service(service_id={'context_id': {'context_uuid': {'uuid': 'admin'}}, 'service_uuid': {'uuid': TOPOLOGY['service_id']}},
        name='Windhof–JFK–Betzdorf [services synthetic]', service_type='SERVICETYPE_QKD', service_endpoint_ids=[endpoint('windhof'), endpoint('betzdorf')],
        service_status={'service_status': 'SERVICESTATUS_ACTIVE' if value['delivery_enabled'] else 'SERVICESTATUS_UPDATING'},
        service_config={'config_rules': [{'action': 'CONFIGACTION_SET', 'custom': {'resource_key': '/transeuroogs/workflow', 'resource_value': json.dumps({
            'owner': 'TransEuroOGS reference orchestrator', 'provisioning': 'TFS NBI/Device commands; not native ServiceService handler',
            'observed_at': value['observed_at'], 'hardware_connected': False, 'delivery_enabled': value['delivery_enabled']})}}]}))


def monitor():
    class HTTP(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in ('/', '/status', '/health'):
                self.send_error(404); return
            path = DATA / 'observation.json'
            if not path.exists(): self.send_error(503); return
            value = json.loads(path.read_text())
            healthy = 'error' not in value and time.time() - value['observed_at'] < 90
            self.send_response(200 if healthy else 503); self.send_header('Content-Type', 'application/json'); self.send_header('Cache-Control', 'no-store'); self.end_headers()
            self.wfile.write(json.dumps(value).encode())
        def log_message(self, *args): pass
    server = ThreadingHTTPServer(('0.0.0.0', 8080), HTTP)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    while True:
        try:
            value = status(); publish(value)
        except Exception as error:
            value = {'observed_at': time.time(), 'error': type(error).__name__, 'hardware_connected': False}
        save(DATA / 'observation.json', value)
        time.sleep(30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['idle', 'monitor', 'bootstrap', 'history', 'retire-interrupted', 'onboard', 'link-intents', 'observe', 'fault-activate', 'activate', 'state', 'ready', 'isolation', 'prepare-held', 'held', 'hold', 'release', 'delivery', 'replay', 'adapter-loop'])
    parser.add_argument('--label', default='normal')
    args = parser.parse_args(); DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.action == 'idle':
        while True: time.sleep(3600)
    elif args.action == 'monitor': monitor()
    elif args.action == 'adapter-loop':
        while True:
            try: observations()
            except Exception as error: print(json.dumps({'adapter_error': type(error).__name__}), flush=True)
            time.sleep(120)
    elif args.action == 'onboard': onboard()
    elif args.action == 'bootstrap':
        onboard(); link_intents()
        if not (DATA / 'workflow.json').exists(): observations()
    elif args.action == 'history': history()
    elif args.action == 'retire-interrupted': retire_interrupted()
    elif args.action == 'link-intents': link_intents()
    elif args.action == 'observe': observations()
    elif args.action in ('fault-activate', 'activate'): activate(args.action == 'fault-activate')
    elif args.action == 'delivery': delivery(args.label)
    elif args.action == 'prepare-held': prepare_delivery('incident')
    elif args.action == 'replay': replay(args.label)
    elif args.action in ('hold', 'release'): protection(args.action)
    elif args.action == 'isolation':
        for name in NODES:
            code, _ = request(name, 'controller-sae', 'GET', '/api/v1/keys/SAE-BETZDORF/enc_keys')
            require(code == 401, 'Controller accessed key plane')
            command = {'command_id': str(uuid.uuid4()), 'expected_revision': manager(name).state()['revision'], 'association': PAIR, 'rule': config(name)['sdn']['applications'][0]['rule']}
            code, _ = request(name, 'observer-sae', 'POST', '/management/v1/commands', command)
            require(code == 403, 'Observer changed policy')
    elif args.action == 'held':
        s = manager('betzdorf').state(); require(s['applications'][0].get('protection_gate') == 'incident_hold', 'Incident gate missing')
        receipt = json.loads((DATA / 'delivery-incident.json').read_text())
        require(receipt['status'] == 'master_delivered', 'Hold test requires keys never delivered to recipient')
        code, _ = request('betzdorf', 'sae-betzdorf', 'POST', '/api/v1/keys/SAE-WINDHOF/dec_keys', {'key_IDs': receipt['ids']})
        require(code == 503, 'Held target delivered')
    elif args.action == 'ready':
        expected = len(json.loads((DATA / 'recovery.json').read_text())['healthy_ids'])
        deadline = time.monotonic() + 50
        while True:
            counts = [manager(name).state()['applications'][0]['counts']['eligible'] for name in ('windhof', 'betzdorf')]
            if counts == [expected, expected]: break
            require(time.monotonic() < deadline, 'Protected relay has not completed; retry the readiness check without reseeding')
            time.sleep(1)
        for link in TOPOLOGY['links']:
            code, result = request(link['provider'], link['source'], 'GET', '/api/v1/keys/LINK-SLAVE/status')
            require(code == 200 and expected <= 128 - result['stored_key_count'] <= 64, 'Independent link key consumption mismatch')
    elif args.action == 'state':
        value = status(); publish(value)
        print(json.dumps({'result': 'PASS', 'action': 'state', 'delivery_enabled': value['delivery_enabled'],
                          'revisions': {n: s['revision'] for n, s in value['nodes'].items()}})); return
    print(json.dumps({'result': 'PASS', 'action': args.action}))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('Service deployment action failed: ' + (str(error) if isinstance(error, (RuntimeError, Incomplete)) else type(error).__name__), file=sys.stderr)
        raise SystemExit(1) from None
