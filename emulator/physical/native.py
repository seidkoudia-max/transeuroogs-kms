"""Use the deployed TeraFlow NBI, Device and Context services in the owned lab."""
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, '/var/teraflow')
import grpc
from common.proto.context_pb2 import DeviceId, Link, Service
from context.client.ContextClient import ContextClient
from device.client.DeviceClient import DeviceClient
from teraflow.controller import ControllerAdapter, NBI
from teraflow.QKDDriver import STATE, ALLOCATION
from emulator.physical import profile

HOST = 'physical-lab.transeuroogs-physical.svc.cluster.local'


def fresh(node, client):
    result = client.stub.GetInitialConfig(DeviceId(device_uuid={'uuid':node}), timeout=20)
    for rule in result.config_rules:
        if rule.WhichOneof('config_rule') == 'custom' and rule.custom.resource_key == STATE:
            value = json.loads(rule.custom.resource_value)
            if value['node_id'] == node: return value
    raise RuntimeError('Fresh native controller state missing')


class Controller:
    def __init__(self, manager):
        self.manager = manager
        self.device = DeviceClient()
        self.context = ContextClient()
        self.nbi = NBI('nbiservice.tfs.svc.cluster.local')
        self.drivers = {name: ControllerAdapter(profile.uid(name), manager(name,'observer-sae'), self.fresh,
                         actor='urn:transeuroogs:sae:controller-sae', nbi=self.nbi) for name in profile.NAMES}

    def fresh(self, node):
        return fresh(node, self.device)

    def close(self):
        self.device.close()
        self.context.close()

    def onboard(self):
        for index, name in enumerate(profile.NAMES):
            settings = {'profile':'transeuroogs-allocation-v1', 'ca_file':'/run/transeuroogs/physical/ca.crt.pem',
                        'cert_file':'/run/transeuroogs/physical/controller-sae.crt.pem', 'key_file':'/run/transeuroogs/physical/controller-sae.key.pem',
                        'server_identity':profile.identity(name), 'timeout':10}
            item = {'device_id':{'device_uuid':{'uuid':profile.uid(name)}}, 'name':profile.LABELS[name]+' [QNETSIM physical lab]',
                    'device_type':'qkd-node', 'device_drivers':['DEVICEDRIVER_QKD'], 'device_config':{'config_rules':[
                        {'action':'CONFIGACTION_SET', 'custom':{'resource_key':'_connect/'+key, 'resource_value':value}}
                        for key,value in [('address',HOST),('port',str(8443+index)),('settings',json.dumps(settings))]]}}
            try: self.context.stub.GetDevice(DeviceId(device_uuid={'uuid':profile.uid(name)}), timeout=20)
            except grpc.RpcError as error:
                if error.code() != grpc.StatusCode.NOT_FOUND: raise
                self.nbi.request('POST','/devices',{'devices':[item]})
            existing = self.nbi.request('GET','/device/'+profile.uid(name))
            if existing['name'] != item['name']: raise RuntimeError('Conflicting native inventory owner')
            self.fresh(profile.uid(name))
        for link in profile.LINKS:
            self.context.SetLink(Link(link_id={'link_uuid':{'uuid':profile.uid(link['id'])}}, name=link['label']+' [QNETSIM synthetic]',
                                         link_endpoint_ids=[endpoint(name,link) for name in (link['source'],link['target'])]))

    def apply(self, name, command):
        if self.drivers[name].SetConfig([(ALLOCATION,command)]) != [True]:
            raise RuntimeError('Controller command lacks exact durable commit evidence')
        return command

    def verify(self, name, link_id, expected):
        actual = self.fresh(profile.uid(name))
        match = next(x for x in actual['links'] if x['catalog']['link_id'] == link_id)
        if match['state']['report'] != expected: raise RuntimeError('TeraFlow did not observe physical telemetry')

    def publish(self, result):
        states = {name:self.fresh(profile.uid(name)) for name in profile.NAMES}
        counts = {name:state['applications'][0]['counts'] for name,state in states.items()}
        context = self.context
        for name, state in states.items():
            device = context.GetDevice(DeviceId(device_uuid={'uuid':profile.uid(name)}))
            for rule in device.device_config.config_rules:
                if rule.WhichOneof('config_rule') == 'custom' and rule.custom.resource_key == STATE:
                    rule.custom.resource_value = json.dumps(state); break
            else:
                rule = device.device_config.config_rules.add(action=1)
                rule.custom.resource_key = STATE; rule.custom.resource_value = json.dumps(state)
            context.SetDevice(device)
        ready = all(counts[name]['eligible'] > 0 for name in ('jfk','hellas'))
        body = dict(result, current_key_buffers=counts, transport='three independently keyed qkd-jwe-v1 hops',
                    architecture='one emulation pod, four independent KMS processes; not production site isolation')
        service = Service(service_id={'context_id':{'context_uuid':{'uuid':'admin'}}, 'service_uuid':{'uuid':profile.uid('service')}},
            name='HellasQCI–Helmos–EAGLE-1–Windhof–JFK [physical emulation]', service_type='SERVICETYPE_QKD',
            service_endpoint_ids=[endpoint('jfk',profile.LINKS[0]), endpoint('hellas',profile.LINKS[-1])],
            service_status={'service_status':'SERVICESTATUS_ACTIVE' if ready else 'SERVICESTATUS_UPDATING'},
            service_config={'config_rules':[{'action':'CONFIGACTION_SET','custom':{'resource_key':'/transeuroogs/physical-emulation', 'resource_value':json.dumps(body)}}]})
        context.SetService(service)
        return body


def endpoint(name, link):
    adjacent = [x for x in profile.LINKS if name in (x['source'],x['target'])]
    return {'device_id':{'device_uuid':{'uuid':profile.uid(name)}}, 'endpoint_uuid':{'uuid':'qkd-'+str(adjacent.index(link)+1)},
            'topology_id':{'context_id':{'context_uuid':{'uuid':'admin'}}, 'topology_uuid':{'uuid':'admin'}}}


def stay(controller, result, output):
    output = Path(output)
    while True:
        try:
            body = controller.publish(result)
            output.write_text(json.dumps(body,indent=2)+'\n')
            (output.parent/'ready').touch()
        except Exception:
            (output.parent/'ready').unlink(missing_ok=True)
            raise
        time.sleep(30)
