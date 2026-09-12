"""Synthetic site profiles; geographic links are not labelled ETSI 020."""
import json
from pathlib import Path

TOPOLOGY = json.loads((Path(__file__).with_name('topology.json')).read_text())
NAMESPACE = TOPOLOGY['namespace']
NODES = {item['name']: item for item in TOPOLOGY['nodes']}
PAIR = TOPOLOGY['association']
CONTROLLER = 'urn:transeuroogs:sae:controller-sae'
INVESTIGATOR = 'urn:transeuroogs:sae:unknown-sae'


def identity(name):
    return 'urn:transeuroogs:kme:' + name


def host(name):
    return name + '.' + NAMESPACE + '.svc.cluster.local'


def config(name):
    node = NODES[name]
    peers, outgoing = {}, []
    for link in TOPOLOGY['links']:
        if name == link['from']:
            target, incoming = link['to'], False
            outgoing.append(target)
        elif name == link['to']:
            target, incoming = link['from'], True
        else:
            continue
        peers[target] = {'url': 'https://' + host(target) + ':8443', 'identity': identity(target),
                         'mode': link['mode'], 'incoming': incoming}
    origin = name == 'windhof'
    local = [PAIR['master']] if origin else ([PAIR['slave']] if name == 'betzdorf' else [])
    rule = {'paused': False, 'allowed_sources': ['synthetic' if origin else 'unknown'],
            'allowed_issuers': [identity(name)] if origin else [p['identity'] for p in peers.values() if p['incoming']],
            'require_evidence': origin, 'allow_satellite': False,
            'max_generation_age_seconds': 3600 if origin else 0,
            'max_local_age_seconds': 3600, 'max_keys_per_request': 16}
    return {'kme_id': name, 'capacity': 1000,
        'identities': {'urn:transeuroogs:sae:sae-windhof': PAIR['master'],
                       'urn:transeuroogs:sae:sae-betzdorf': PAIR['slave']}, 'associations': [PAIR],
        'inter_kms': {'public_url': 'https://' + host(name) + ':8443', 'identity': identity(name),
            'state_dir': '/state/private', 'local_saes': local, 'peers': peers,
            'routes': {PAIR['slave']: outgoing} if outgoing else {},
            'target_kmes': {PAIR['slave']: 'betzdorf'}},
        'metadata': {'domain': node['domain'], 'issuer': identity(name), 'namespace': 'lux-' + name,
            'credential_id': 'lux-lab-v1', 'signing_key_file': '/run/private/material/signing.key.pem',
            'max_events': 8192, 'clock_uncertainty_ms': 0, 'readers': {INVESTIGATOR: [PAIR]}},
        'sdn': {'node_id': node['node_id'], 'location': 'Synthetic ' + node['site'], 'max_commands': 256,
            'applications': [{'app_id': TOPOLOGY['app_id'], 'remote_node_id': NODES['betzdorf' if origin else 'windhof']['node_id'],
                              'association': PAIR, 'rule': rule}],
            'principals': {CONTROLLER: {'associations': [PAIR], 'write': True, 'routes': False}}}}
