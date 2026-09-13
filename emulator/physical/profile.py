"""Isolated Helmos/HellasQCI–Windhof/Lux4QCI KMS deployment profile."""
import json
from pathlib import Path

IDS = json.loads(Path(__file__).with_name('inventory-ids.json').read_text())

NAMESPACE = 'transeuroogs-physical'
PAIR = {'master': 'SAE-JFK', 'slave': 'SAE-HELLAS'}
NAMES = ('jfk', 'windhof', 'helmos', 'hellas')
LABELS = {'jfk':'JFK Kirchberg · Lux4QCI', 'windhof':'Windhof OGS · Lux4QCI',
          'helmos':'Helmos OGS · HellasQCI', 'hellas':'HellasQCI terrestrial node'}
LINKS = [dict(id='fiber-windhof-jfk', source='jfk', target='windhof', provider='link-lux', label='25 km fibre QKD'),
         dict(id='eagle-offline-windhof-helmos', source='windhof', target='helmos', provider='eagle-pair', label='EAGLE-1 offline paired-key service'),
         dict(id='fiber-helmos-hellas', source='helmos', target='hellas', provider='link-hellas', label='30 km fibre QKD')]


def uid(name): return IDS[name]
def identity(name): return 'urn:transeuroogs:kme:'+name
def domain(name): return 'Lux4QCI' if name in ('jfk','windhof') else 'HellasQCI'
def pool(name): return domain(name)+'/'+name+'/JFK-HellasQCI'


def config(name, urls, root, pki, *, control=True):
    index = NAMES.index(name); origin = index == 0
    remote = {'jfk':'hellas', 'windhof':'helmos', 'helmos':'windhof', 'hellas':'jfk'}[name]
    adjacent = [link for link in LINKS if name in (link['source'],link['target'])]
    peers, outgoing = {}, []
    for link in adjacent:
        incoming = name == link['target']; other = link['source'] if incoming else link['target']
        peers[other] = {'url': urls[other], 'identity': identity(other), 'incoming': incoming, 'mode': 'qkd-jwe-v1',
            'link_key_source': {'profile':'etsi014-link-uuidv4-256-v1', 'interface_agreement':'synthetic-physical-lab-only',
                'url':urls[link['provider']], 'server_identity':identity(link['provider']), 'gateway_identity':identity(name),
                'gateway_master':'LINK-MASTER', 'gateway_slave':'LINK-SLAVE', 'role':'slave' if incoming else 'master',
                'remote_kme_id':link['provider'], 'pki_dir':str(pki), 'certificate_name':name,
                'state_dir':str(root/name/('intake-'+other)), 'lifetime_seconds':3600}}
        if not incoming: outgoing.append(other)
    cfg = {'kme_id':name, 'capacity':256, 'associations':[PAIR],
        'identities':{'urn:transeuroogs:sae:sae-jfk':PAIR['master'], 'urn:transeuroogs:sae:sae-hellas':PAIR['slave']},
        'inter_kms': {'public_url':urls[name], 'identity':identity(name), 'state_dir':str(root/name/'state'),
            'qkd_state_dir':str(root/name/'protected'), 'local_saes':[PAIR['master']] if origin else ([PAIR['slave']] if name == 'hellas' else []),
            'peers':peers, 'routes':{PAIR['slave']:outgoing} if outgoing else {}, 'target_kmes':{PAIR['slave']:'hellas'}}}
    cfg['federation'] = {'profile':'transeuroogs-federation-v1', 'max_actions':256,
        'principals': {'urn:transeuroogs:sae:protection-sae': {'pools':[pool(name)], 'operate':True}},
        'pools':[{'binding':{'pool_id':pool(name), 'remote_pool_id':pool(remote), 'binding_revision':1,
                            'service_id':'JFK-HellasQCI-physical', 'service_epoch':'synthetic-1', 'purpose':'application-tls'},
                  'domain_id':domain(name), 'ogs_id':'Windhof' if domain(name) == 'Lux4QCI' else 'Helmos',
                  'remote_domain_id':domain(remote), 'remote_ogs_id':'Helmos' if domain(remote) == 'HellasQCI' else 'Windhof',
                  'association':PAIR, 'provider_identity':'urn:transeuroogs:synthetic:physical-relay',
                  'gateway_pair':{'master':'GW-WINDHOF','slave':'GW-HELMOS'}, 'mapping_authority':'synthetic-lab',
                  'contract':{'mode':'synthetic'}, 'require_provider_evidence':False}]}
    if not control: return cfg
    cfg['metadata'] = {'domain':domain(name), 'issuer':identity(name), 'namespace':'physical-'+name,
        'credential_id':'synthetic-v1', 'signing_key_file':str(root/name/'sign.pem'), 'state_dir':str(root/name/'state'),
        'max_events':16384, 'clock_uncertainty_ms':0, 'readers':{'urn:transeuroogs:sae:unknown-sae':[PAIR]}}
    rule = {'paused':False, 'allowed_sources':['synthetic' if origin else 'unknown'],
            'allowed_issuers':[identity(name)] if origin else [item['identity'] for item in peers.values() if item['incoming']],
            'require_evidence':origin, 'allow_satellite':True, 'max_generation_age_seconds':3600 if origin else 0,
            'max_local_age_seconds':3600, 'max_keys_per_request':32}
    cfg['sdn'] = {'node_id':uid(name), 'location':LABELS[name]+' [physical synthetic]', 'max_commands':10000,
        'applications':[{'app_id':uid('application'), 'association':PAIR, 'remote_node_id':uid(remote), 'rule':rule}],
        'principals':{'urn:transeuroogs:sae:controller-sae':{'associations':[PAIR], 'write':True,'services':True},
                      'urn:transeuroogs:sae:observer-sae':{'associations':[PAIR]},
                      'urn:transeuroogs:sae:adapter-sae':{'associations':[PAIR], 'telemetry':True}},
        'services':{'links':[]}}
    for interface, link in enumerate(adjacent, 1):
        other = link['target'] if name == link['source'] else link['source']
        remote_links = [x for x in LINKS if other in (x['source'], x['target'])]
        cfg['sdn']['services']['links'].append({'link_id':uid(link['id']), 'association':PAIR, 'local_interface':interface,
            'remote_interface':remote_links.index(link)+1, 'remote_node_id':uid(other), 'model':link['label']+' [conditional simulation]',
            'technology':'DV-QKD', 'adapter_identity':'urn:transeuroogs:sae:adapter-sae', 'mode':'synthetic', 'observation_ttl_seconds':600})
    return cfg
