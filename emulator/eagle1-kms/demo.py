"""Three-segment synthetic service demo with separate QCI-LU, SES and QCI-GR CAs.

The harness supplies application key-ID notification in memory. It does not
implement an application security protocol or any SES satellite protocol.
"""
import argparse
import http.client
import json
import pathlib
import secrets
import selectors
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse

def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def context(ca_dir, identity_dir, name):
    ctx = ssl.create_default_context(cafile=str(ca_dir / "ca.crt.pem"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_flags |= ssl.VERIFY_X509_STRICT
    if name:
        ctx.load_cert_chain(identity_dir / (name + ".crt.pem"), identity_dir / (name + ".key.pem"))
    return ctx


def call(url, ctx, identity, path, body=None):
    parsed = urllib.parse.urlsplit(url)
    conn = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=ctx, timeout=6)
    try:
        conn.connect()
        uris = [v for k, v in conn.sock.getpeercert().get("subjectAltName", ()) if k == "URI"]
        require(uris == [identity], "Server identity mismatch")
        conn.request("POST" if body is not None else "GET", path,
                     body=None if body is None else json.dumps(body),
                     headers={"Content-Type": "application/json"})
        res = conn.getresponse()
        data = res.read(65537)
        require(len(data) <= 65536, "Oversized response")
        return res.status, json.loads(data) if data else {}
    finally:
        conn.close()


class Processes:
    def __init__(self):
        self.running = {}

    def start(self, name, args):
        p = subprocess.Popen([str(a) for a in args], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True)
        self.running[name] = p
        with selectors.DefaultSelector() as sel:
            sel.register(p.stdout, selectors.EVENT_READ)
            require(bool(sel.select(timeout=12)), "Startup timed out: " + name)
        line = p.stdout.readline()
        require(bool(line), "Startup failed: " + name)
        event = json.loads(line)
        require(event.get("event") == "listening", "Readiness missing: " + name)
        return event

    def crash(self, name):
        p = self.running.pop(name)
        p.kill()
        p.communicate(timeout=5)

    def close(self):
        for p in self.running.values():
            p.terminate()
        for p in self.running.values():
            try:
                p.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                p.kill()
                p.communicate()


def exercise(args, directory, procs):
    metadata = None
    if args.metadata_binary:
        from metadata_lab import MetadataLab
        metadata = MetadataLab(args.metadata_binary, directory, require)
    pki = {name: directory / (name + "-pki") for name in ("ses", "lu", "gr")}
    for dest in pki.values():
        subprocess.run([str(args.pki_binary), "--out", str(dest)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    count = 64
    services = procs.start("ses", [args.emulator, "--pki-dir", pki["ses"],
                                   "--synthetic-keys", count, "--ready-delay", "2s"])["services"]
    provider_ctx = context(pki["ses"], pki["ses"], "lu")
    code, inventory = call(services["GW-LU"], provider_ctx, "urn:transeuroogs:kme:eagle-lu",
                           "/api/v1/keys/GW-GR/status")
    require(code == 200 and inventory["stored_key_count"] == 0, "Delayed keys exposed early")
    configs, urls = {}, {}
    for site, local, role, gateway in (("lu", "SAE-LU", "master", "GW-LU"), ("gr", "SAE-GR", "slave", "GW-GR")):
        cfg = {
            "kme_id": site, "capacity": 256,
            "identities": {"urn:transeuroogs:sae:sae-lu": "SAE-LU", "urn:transeuroogs:sae:sae-gr": "SAE-GR"},
            "local_saes": [local], "associations": [{"master": "SAE-LU", "slave": "SAE-GR"}],
            "eagle": {
                "profile": "synthetic-segmented-v1", "url": services[gateway],
                "server_identity": "urn:transeuroogs:kme:eagle-" + site,
                "gateway_identity": "urn:transeuroogs:kme:" + site,
                "gateway_master": "GW-LU", "gateway_slave": "GW-GR", "role": role,
                "remote_kme_id": "gr" if site == "lu" else "lu",
                "state_dir": str(directory / (site + "-state")),
                "pki_dir": str(pki["ses"]), "certificate_name": site, "lifetime_seconds": 60,
            },
        }
        if args.federation:
            peer = "gr" if site == "lu" else "lu"
            pool_id = site.upper() + "/OGS/to-" + peer.upper() + "/final"
            cfg["federation"] = {
                "profile": "transeuroogs-federation-v1", "max_actions": 128,
                "principals": {"urn:transeuroogs:sae:unknown-sae": {"pools": [pool_id], "operate": True}},
                "provider_trust": [], "pools": [{
                    "binding": {"pool_id": pool_id, "remote_pool_id": peer.upper() + "/OGS/to-" + site.upper() + "/final",
                                "binding_revision": 1 if site == "lu" else 3, "service_id": "synthetic-LU-GR-final",
                                "service_epoch": "lab-1", "purpose": "application-tls"},
                    "domain_id": site.upper(), "ogs_id": "OGS-" + site.upper(), "remote_domain_id": peer.upper(), "remote_ogs_id": "OGS-" + peer.upper(),
                    "association": cfg["associations"][0], "provider_identity": cfg["eagle"]["server_identity"],
                    "gateway_pair": {"master": "GW-LU", "slave": "GW-GR"}, "mapping_authority": "synthetic-provisioning",
                    "contract": {"mode": "synthetic"}, "require_provider_evidence": False, "max_generation_age_seconds": 0}]}
        if metadata:
            metadata.configure(cfg, site)
        path = directory / (site + ".json")
        path.write_text(json.dumps(cfg, indent=2) + "\n")
        configs[site] = [args.binary, "--config", path, "--pki-dir", pki[site],
                         "--certificate-name", site, "--listen", "127.0.0.1:0"]
        urls[site] = "https://" + procs.start(site, configs[site])["address"]
    contexts = {site: context(pki[site], pki[site], "sae-" + site) for site in ("lu", "gr")}

    def local(site, path, body=None, ctx=None):
        return call(urls[site], ctx or contexts[site], "urn:transeuroogs:kme:" + site, path, body)

    status = "/api/v1/keys/SAE-GR/status"
    # A valid certificate from the local CA still cannot impersonate a remote SAE.
    code, _ = local("lu", status, ctx=context(pki["lu"], pki["lu"], "sae-gr"))
    require(code == 401, "Non-local identity accepted")
    for identity_dir, name in ((pki["gr"], "sae-lu"), (pki["ses"], "lu"), (pki["lu"], None)):
        denied = False
        try:
            local("lu", status, ctx=context(pki["lu"], identity_dir, name))
        except (ssl.SSLError, http.client.HTTPException, OSError):
            denied = True
        require(denied, "Wrong segment credentials or absent certificate accepted")
    code, _ = call(services["GW-LU"], context(pki["ses"], pki["ses"], "gr"),
                   "urn:transeuroogs:kme:eagle-lu", "/api/v1/keys/GW-GR/status")
    require(code == 401, "Wrong gateway accepted at local ground service")

    deadline = time.monotonic() + 15
    while True:
        code, inventory = local("lu", status)
        if code == 200 and inventory["stored_key_count"] == count:
            break
        require(time.monotonic() < deadline, "Final-key inventory never became available")
        time.sleep(0.05)
    if args.federation:
        import uuid
        operator = context(pki["lu"], pki["lu"], "unknown-sae")
        code, view = local("lu", "/federation/v1/state")
        require(code == 200 and len(view["pools"]) == 1 and len(view["pools"][0]["needed_SES_input"]) == 10, "Missing SES inputs not exposed")
        incident = str(uuid.uuid4())
        command = {"action_id": str(uuid.uuid4()), "incident_id": incident, "pool_id": "LU/OGS/to-GR/final",
                   "expected_revision": 0, "operation": "hold", "reason": "synthetic incident exercise"}
        code, _ = local("lu", "/federation/v1/actions", command)
        require(code == 403, "Application gained operator authority")
        for _ in range(2):
            code, result = local("lu", "/federation/v1/actions", command, ctx=operator)
            require(code == 200 and result["revision"] == 1, "Incident hold or exact replay failed")
        code, _ = local("lu", "/api/v1/keys/SAE-GR/enc_keys", {"number": 1})
        require(code == 503, "Hold did not stop allocation")
        procs.crash("lu")
        urls["lu"] = "https://" + procs.start("lu", configs["lu"])["address"]
        code, _ = local("lu", "/api/v1/keys/SAE-GR/enc_keys", {"number": 1})
        require(code == 503, "Restart lost incident hold")
        command.update(action_id=str(uuid.uuid4()), expected_revision=1, operation="release")
        code, _ = local("lu", "/federation/v1/actions", command, ctx=operator)
        require(code == 200, "Hold release failed")
    seen, previous = set(), None
    for batch in range(count // 8):
        code, first = local("lu", "/api/v1/keys/SAE-GR/enc_keys", {"number": 8})
        require(code == 200 and len(first["keys"]) == 8, "Master delivery failed (HTTP " + str(code) + ")")
        ids = [{"key_ID": k["key_ID"]} for k in first["keys"]]
        require(not seen.intersection(k["key_ID"] for k in first["keys"]), "Reused KID")
        if batch == 0:
            procs.crash("lu")
        if previous:
            code, _ = local("gr", "/api/v1/keys/SAE-LU/dec_keys", {"key_IDs": [previous, ids[0]]})
            require(code == 503, "Mixed replay batch accepted")
        # This is application KID notification, not a KMS control/transfer link.
        code, second = local("gr", "/api/v1/keys/SAE-LU/dec_keys", {"key_IDs": ids})
        require(code == 200 and len(second["keys"]) == 8, "Slave delivery failed")
        for a, b in zip(first["keys"], second["keys"]):
            require(a["key_ID"] == b["key_ID"] and secrets.compare_digest(a["key"], b["key"]), "Endpoint copies differ")
            seen.add(a["key_ID"])
        previous = ids[-1]
        if batch == 0:
            urls["lu"] = "https://" + procs.start("lu", configs["lu"])["address"]
            procs.crash("gr")
            urls["gr"] = "https://" + procs.start("gr", configs["gr"])["address"]
        code, _ = local("gr", "/api/v1/keys/SAE-LU/dec_keys", {"key_IDs": ids})
        require(code == 503, "Consumed keys reissued, including after restart")
    code, inventory = local("lu", status)
    require(code == 200 and inventory["stored_key_count"] == 0, "Pool not depleted")
    code, _ = local("lu", "/api/v1/keys/SAE-GR/enc_keys", {"number": 1})
    require(code == 503, "Exhausted upstream supplied a key")
    if metadata:
        metadata.verify(local, pki, context, previous["key_ID"])
    print(json.dumps({"result": "PASS", "matching_keys": len(seen), "independent_trust_domains": 3,
                      "local_authentication": True, "kid_preserved": True, "delayed_availability": True,
                      "replay_rejected_after_restart": True, "slave_works_with_master_kms_offline": True,
                      "satellite_cryptography_simulated": False, "pool_and_incident_controls": args.federation}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--emulator", required=True, type=pathlib.Path)
    parser.add_argument("--pki-binary", required=True, type=pathlib.Path)
    parser.add_argument("--metadata-binary", type=pathlib.Path)
    parser.add_argument("--federation", action="store_true")
    args = parser.parse_args()
    for field in ("binary", "emulator", "pki_binary"):
        setattr(args, field, getattr(args, field).resolve())
    if args.metadata_binary:
        args.metadata_binary = args.metadata_binary.resolve()
    procs = Processes()
    try:
        with tempfile.TemporaryDirectory(prefix="transeuroogs-segmented-") as tmp:
            try:
                exercise(args, pathlib.Path(tmp), procs)
            finally:
                procs.close()
    except (RuntimeError, OSError, ValueError, KeyError, http.client.HTTPException, subprocess.SubprocessError) as exc:
        detail = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
        print("Segmented laboratory failed: " + detail + ". No key data displayed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
