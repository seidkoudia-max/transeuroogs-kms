#!/usr/bin/env python3
"""Run in the lab-client pod. Never print key material or private credentials."""
import argparse
import http.client
import json
from pathlib import Path
import ssl
import sys
import uuid

from common.proto.context_pb2 import Context, Topology, Device
from context.client.ContextClient import ContextClient
from device.client.DeviceClient import DeviceClient
from device.service.drivers.transeuroogs.client import Client, ManagementError
from device.service.drivers.transeuroogs.policy import Reconciler
from device.service.drivers.transeuroogs.QKDDriver import STATE

PKI = '/run/lab-clients/'
NODE = '97ee65bc-1587-4e48-843d-4a9fbcfc6cce'
PAIR = {'master': 'SAE-LU', 'slave': 'SAE-GR'}
RESOURCE = '/transeuroogs/allocation'
OUTBOX = Path('/state/private/pending-policy.json')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def manager(identity='controller-sae', server_identity='urn:transeuroogs:kme:LU-KMS'):
    return Client('kms', 8443, ca_file=PKI + 'ca.crt.pem', cert_file=PKI + identity + '.crt.pem',
                  key_file=PKI + identity + '.key.pem', server_identity=server_identity, timeout=10)


def key_request(identity, method, path, body=None):
    context = ssl.create_default_context(cafile=PKI + 'ca.crt.pem')
    context.load_cert_chain(PKI + identity + '.crt.pem', PKI + identity + '.key.pem')
    connection = http.client.HTTPSConnection('kms', 8443, context=context, timeout=10)
    try:
        connection.request(method, path, body=None if body is None else json.dumps(body),
                           headers={'Content-Type': 'application/json'})
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def nbi(method, path, body=None):
    connection = http.client.HTTPConnection('nbiservice', 8080, timeout=90)
    try:
        connection.request(method, '/tfs-api' + path,
                           body=None if body is None else json.dumps(body), headers={'Content-Type': 'application/json'})
        response = connection.getresponse()
        value = json.loads(response.read())
        require(200 <= response.status < 300, 'TeraFlow NBI returned HTTP ' + str(response.status))
        return value
    finally:
        connection.close()


def device():
    settings = {'profile': 'transeuroogs-allocation-v1', 'ca_file': '/run/transeuroogs/mtls/ca.crt.pem',
                'cert_file': '/run/transeuroogs/mtls/controller.crt.pem',
                'key_file': '/run/transeuroogs/mtls/controller.key.pem',
                'server_identity': 'urn:transeuroogs:kme:LU-KMS', 'timeout': 10}
    return {'device_id': {'device_uuid': {'uuid': NODE}}, 'name': 'LU-KMS', 'device_type': 'qkd-node',
            'device_drivers': ['DEVICEDRIVER_QKD'], 'device_config': {'config_rules': [
                {'action': 'CONFIGACTION_SET', 'custom': {'resource_key': '_connect/' + key, 'resource_value': value}}
                for key, value in [('address', 'kms'), ('port', '8443'), ('settings', json.dumps(settings))]]}}


def onboard(use_nbi):
    context = ContextClient()
    context_id = context.SetContext(Context(context_id={'context_uuid': {'uuid': 'admin'}}, name='admin'))
    context.SetTopology(Topology(topology_id={'context_id': context_id,
                                            'topology_uuid': {'uuid': 'admin'}}, name='admin'))
    item = device()
    if use_nbi:
        nbi('POST', '/devices', {'devices': [item]})
        discovered = nbi('GET', '/device/' + NODE)
        rules = discovered['device_config']['config_rules']
        require(any('__node__' in r.get('custom', {}).get('resource_key', '') for r in rules), 'Node discovery absent')
    else:
        DeviceClient().AddDevice(Device(**item))
    require(manager().state()['applications'][0]['association'] == PAIR, 'Wrong KMS association')


def set_policy(paused, use_nbi):
    state = manager().state()
    rule = dict(state['applications'][0]['rule'], paused=paused)
    command = {'command_id': str(uuid.uuid4()), 'expected_revision': state['revision'], 'association': PAIR, 'rule': rule}
    request = {'device_id': {'device_uuid': {'uuid': NODE}}, 'device_config': {'config_rules': [
        {'action': 'CONFIGACTION_SET', 'custom': {'resource_key': RESOURCE, 'resource_value': json.dumps(command)}}]}}
    if use_nbi:
        nbi('PUT', '/device/' + NODE, request)
        nbi('PUT', '/device/' + NODE, request)
    else:
        DeviceClient().ConfigureDevice(Device(**request))
        DeviceClient().ConfigureDevice(Device(**request))
    after = manager().state()
    require(after['revision'] == state['revision'] + 1, 'Policy replay changed revision')
    require(after['applications'][0]['rule']['paused'] == paused, 'Policy not applied')
    return after['revision']


class NBIAdapter:
    """Observe metadata over mTLS; send every write through real TFS NBI/Device."""
    def GetConfig(self, keys):
        require(keys == [STATE], 'Unexpected observation')
        return [(STATE, manager().state())]

    def SetConfig(self, resources):
        require(len(resources) == 1 and resources[0][0] == RESOURCE, 'Unexpected mutation')
        request = {'device_id': {'device_uuid': {'uuid': NODE}}, 'device_config': {'config_rules': [
            {'action': 'CONFIGACTION_SET', 'custom': {'resource_key': RESOURCE,
                                                   'resource_value': json.dumps(resources[0][1])}}]}}
        nbi('PUT', '/device/' + NODE, request)
        return [True]


def lost_reply(start):
    OUTBOX.parent.mkdir(mode=0o700, exist_ok=True)
    if start:
        require(not OUTBOX.exists(), 'Resolve existing pending operation first')
        before = manager().state()
        desired = {'association': PAIR, 'rule': dict(before['applications'][0]['rule'], paused=True)}
        require(not before['applications'][0]['rule']['paused'], 'Resume before the lost-reply test')

        class LoseResult(NBIAdapter):
            def SetConfig(self, resources):
                super().SetConfig(resources)
                # Inject loss after the real controller has committed the command.
                return [ManagementError()]

        try:
            Reconciler(LoseResult(), OUTBOX).reconcile(desired)
        except RuntimeError:
            require(OUTBOX.exists(), 'Uncertain command not persisted')
        else:
            raise RuntimeError('Lost reply not reported')
        require(manager().state()['revision'] == before['revision'] + 1, 'Fault was not injected after commit')
    else:
        require(OUTBOX.exists(), 'No pending command to recover')
        envelope = json.loads(OUTBOX.read_text())
        expected = envelope['command']['expected_revision'] + 1
        result = Reconciler(NBIAdapter(), OUTBOX).reconcile(envelope['desired'])
        require(result['revision'] == expected and not OUTBOX.exists(), 'Pending replay failed')
        require(manager().state()['revision'] == expected, 'Restart replay created a second command')
        require(not Reconciler(NBIAdapter(), OUTBOX).reconcile(envelope['desired'])['changed'], 'Convergence created a new command')


def discovery():
    found = nbi('GET', '/device/' + NODE)
    require(found['name'] == 'LU-KMS', 'Persisted device was not recovered')


def history():
    after, watermark, controls = 0, None, 0
    while True:
        path = '/metadata/v1/events?after=' + str(after)
        if watermark is not None:
            path += '&through=' + str(watermark)
        code, data = key_request('unknown-sae', 'GET', path)
        require(code == 200, 'Investigator history unavailable')
        page = data['page']
        watermark = page['watermark']
        controls += sum('control' in item['event'] for item in page['events'])
        if page['page_complete']:
            break
        require(page['next'] > after, 'History did not advance')
        after = page['next']
    require(controls == manager().state()['revision'], 'Policy events missing or duplicated')


def isolation():
    for identity in ('sae-lu', 'unknown-sae'):
        try:
            manager(identity).state()
        except ManagementError:
            pass
        else:
            raise RuntimeError('Non-controller accessed management')
    try:
        manager(server_identity='urn:transeuroogs:kme:wrong').state()
    except ManagementError:
        pass
    else:
        raise RuntimeError('Wrong KMS URI identity accepted')
    for path in ('/api/v1/keys/SAE-GR/enc_keys', '/metadata/v1/events'):
        code, _ = key_request('controller-sae', 'GET', path)
        require(code == 401, 'Controller obtained key-plane or investigator access')


def delivery():
    code, first = key_request('sae-lu', 'POST', '/api/v1/keys/SAE-GR/enc_keys', {'number': 2, 'size': 256})
    require(code == 200, 'Master delivery failed')
    ids = [{'key_ID': key['key_ID']} for key in first['keys']]
    code, second = key_request('sae-gr', 'POST', '/api/v1/keys/SAE-LU/dec_keys', {'key_IDs': ids})
    require(code == 200 and first == second, 'Paired keys did not match')
    del first, second
    code, _ = key_request('sae-gr', 'POST', '/api/v1/keys/SAE-LU/dec_keys', {'key_IDs': ids})
    require(code == 503, 'Duplicate recipient delivery accepted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('onboard', 'pause', 'resume', 'paused', 'isolation', 'delivery', 'state',
                                         'lost-start', 'lost-recover', 'discovery', 'history'))
    parser.add_argument('--nbi', action='store_true')
    args = parser.parse_args()
    if args.action == 'onboard':
        onboard(args.nbi)
    elif args.action in ('pause', 'resume'):
        set_policy(args.action == 'pause', args.nbi)
    elif args.action == 'paused':
        code, _ = key_request('sae-lu', 'GET', '/api/v1/keys/SAE-GR/enc_keys')
        require(code == 503, 'Paused KMS delivered keys')
    elif args.action == 'isolation':
        isolation()
    elif args.action == 'delivery':
        delivery()
    elif args.action in ('lost-start', 'lost-recover'):
        lost_reply(args.action == 'lost-start')
    elif args.action == 'discovery':
        discovery()
    elif args.action == 'history':
        history()
    state = manager().state()
    via_tfs = args.action in ('onboard', 'pause', 'resume', 'lost-start', 'lost-recover', 'discovery')
    print(json.dumps({'result': 'PASS', 'action': args.action, 'revision': state['revision'],
                      'paused': state['applications'][0]['rule']['paused'],
                      'transport': ('TeraFlow NBI' if args.nbi or args.action.startswith('lost-') or args.action == 'discovery'
                                    else 'TeraFlow gRPC') if via_tfs else 'KMS mTLS'}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Error payloads may carry data. Print only controlled assertions or the type.
        detail = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print('Cluster acceptance failed: ' + detail, file=sys.stderr)
        sys.exit(1)
