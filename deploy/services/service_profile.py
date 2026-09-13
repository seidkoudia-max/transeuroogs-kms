"""Locally approved synthetic sites, pools and independently consumed 014 links."""
import json
from pathlib import Path

TOPOLOGY = json.loads(Path(__file__).with_name("topology.json").read_text())
NAMESPACE = TOPOLOGY["namespace"]
NODES = {n["name"]: n for n in TOPOLOGY["nodes"]}
PAIR = TOPOLOGY["association"]
ACTOR = "urn:transeuroogs:sae:controller-sae"
OBSERVER = "urn:transeuroogs:sae:observer-sae"
ADAPTER = "urn:transeuroogs:sae:adapter-sae"
PROTECTION = "urn:transeuroogs:sae:protection-sae"
INVESTIGATOR = "urn:transeuroogs:sae:unknown-sae"


def identity(name):
    return "urn:transeuroogs:kme:" + name


def host(name):
    return name + "." + NAMESPACE + ".svc.cluster.local"


def metadata(name):
    return {"domain": "LU-services-lab", "issuer": identity(name), "namespace": "services-" + name,
            "credential_id": "synthetic-v1", "signing_key_file": "/run/private/material/signing.key.pem",
            "state_dir": "/state/private", "max_events": 32768, "clock_uncertainty_ms": 0, "readers": {INVESTIGATOR: [PAIR]}}


def config(name):
    if name.startswith("link-"):
        link = next(l for l in TOPOLOGY["links"] if l["provider"] == name)
        pair = {"master": "LINK-MASTER", "slave": "LINK-SLAVE"}
        meta = metadata(name); meta["readers"] = {INVESTIGATOR: [pair]}
        return {"kme_id": name, "capacity": 256, "associations": [pair],
                "identities": {identity(link["source"]): pair["master"], identity(link["target"]): pair["slave"]}, "metadata": meta}
    index = list(NODES).index(name); origin = index == 0
    peers = {}; outgoing = []
    for number in (index - 1, index + 1):
        if not 0 <= number < len(NODES): continue
        peer = list(NODES)[number]; incoming = number < index
        link = next((l for l in TOPOLOGY["links"] if {name, peer} == {l["source"], l["target"]}), None)
        item = {"url": "https://" + host(peer) + ":8443", "identity": identity(peer), "incoming": incoming,
                "mode": "qkd-jwe-v1" if link else "etsi020"}
        if link:
            item["link_key_source"] = {"profile": "etsi014-link-uuidv4-256-v1", "interface_agreement": "synthetic-lab-only",
                "url": "https://" + host(link["provider"]) + ":8443", "server_identity": identity(link["provider"]),
                "gateway_identity": identity(name), "gateway_master": "LINK-MASTER", "gateway_slave": "LINK-SLAVE",
                "role": "slave" if incoming else "master", "remote_kme_id": link["provider"], "pki_dir": "/run/pki",
                "certificate_name": name, "state_dir": "/state/link-intake", "lifetime_seconds": 86400}
        peers[peer] = item
        if not incoming: outgoing.append(peer)
    link = next(l for l in TOPOLOGY["links"] if name in (l["source"], l["target"]))
    neighbor = link["target"] if name == link["source"] else link["source"]
    rule = {"paused": False, "allowed_sources": ["synthetic" if origin else "unknown"],
            "allowed_issuers": [identity(name)] if origin else [p["identity"] for p in peers.values() if p["incoming"]],
            "require_evidence": origin, "allow_satellite": False, "max_generation_age_seconds": 86400 if origin else 0,
            "max_local_age_seconds": 86400, "max_keys_per_request": 16}
    remote = "betzdorf" if origin else "windhof"
    binding = {"pool_id": "LU/" + name + "/services-final", "remote_pool_id": "LU/" + remote + "/services-final",
               "service_id": TOPOLOGY["service_id"], "service_epoch": "services-lab-1", "binding_revision": 1, "purpose": "application-tls"}
    return {"kme_id": name, "capacity": 256, "associations": [PAIR],
        "identities": {"urn:transeuroogs:sae:sae-windhof": PAIR["master"], "urn:transeuroogs:sae:sae-betzdorf": PAIR["slave"]},
        "metadata": metadata(name),
        "inter_kms": {"public_url": "https://" + host(name) + ":8443", "identity": identity(name), "state_dir": "/state/private",
            "qkd_state_dir": "/state/protected", "local_saes": [PAIR["master"]] if origin else ([PAIR["slave"]] if name == "betzdorf" else []),
            "peers": peers, "routes": {PAIR["slave"]: outgoing} if outgoing else {}, "target_kmes": {PAIR["slave"]: "betzdorf"}},
        "federation": {"profile": "transeuroogs-federation-v1", "max_actions": 1024, "principals": {PROTECTION: {"pools": [binding["pool_id"]], "operate": True}},
            "pools": [{"binding": binding, "domain_id": "LU-services-lab", "ogs_id": NODES[name]["label"],
                       "remote_domain_id": "LU-services-lab", "remote_ogs_id": NODES[remote]["label"], "association": PAIR,
                       "provider_identity": "urn:transeuroogs:synthetic:terrestrial-relay", "gateway_pair": {"master": "GW-WINDHOF", "slave": "GW-BETZDORF"},
                       "mapping_authority": "synthetic-provisioning", "contract": {"mode": "synthetic"}, "require_provider_evidence": False}]},
        "sdn": {"node_id": NODES[name]["node_id"], "location": NODES[name]["label"] + " [services synthetic]", "max_commands": 10000,
                "applications": [{"app_id": TOPOLOGY["app_id"], "association": PAIR, "remote_node_id": NODES[remote]["node_id"], "rule": rule}],
                "principals": {ACTOR: {"associations": [PAIR], "write": True, "services": True}, OBSERVER: {"associations": [PAIR]}, ADAPTER: {"associations": [PAIR], "telemetry": True}},
                "services": {"links": [{"link_id": link["link_id"], "association": PAIR, "local_interface": 1, "remote_interface": 1,
                    "remote_node_id": NODES[neighbor]["node_id"], "model": link["vendor"] + " [synthetic]", "technology": "DV-QKD",
                    "adapter_identity": ADAPTER, "mode": "synthetic", "observation_ttl_seconds": 600}]}}}
