"""Real PostgreSQL, synthetic Eagle-1 and independent application processes."""
import argparse
import importlib.util
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src/application"))
import session

spec = importlib.util.spec_from_file_location("segmented", ROOT / "emulator/eagle1-kms/demo.py")
segmented = importlib.util.module_from_spec(spec)
spec.loader.exec_module(segmented)


def profile(directory, name, identity, application=False, trust=None):
    trust = trust or directory
    return {"ca": str(trust / "ca.crt.pem"), "crls": [str(trust / "ca.crl.pem")],
            "cert": str(directory / (name + ".crt.pem")), "key": str(directory / (name + ".key.pem")),
            "identity": identity, "application": application}


def write(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def exercise(args, root, processes):
    pki = {name: root / (name + "-pki") for name in ("ses", "lu", "gr", "application")}
    for directory in pki.values():
        subprocess.run([str(args.pki), "--out", str(directory)], check=True, stdout=subprocess.DEVNULL)
    services = processes.start("ses", [args.emulator, "--pki-dir", pki["ses"], "--synthetic-keys", "16", "--ready-delay", "0s"])["services"]
    configs, commands, urls = {}, {}, {}
    for site, local, role, gateway in (("lu", "SAE-LU", "master", "GW-LU"), ("gr", "SAE-GR", "slave", "GW-GR")):
        keyring = root / (site + "-wrapping")
        keyring.mkdir(mode=0o700)
        (keyring / "v1.key").write_bytes(os.urandom(32)); (keyring / "v1.key").chmod(0o600)
        (keyring / "active").write_text("v1"); (keyring / "active").chmod(0o600)
        cfg = {
            "kme_id": site, "capacity": 128,
            "identities": {"urn:transeuroogs:sae:sae-lu": "SAE-LU", "urn:transeuroogs:sae:sae-gr": "SAE-GR"},
            "local_saes": [local], "associations": [{"master": "SAE-LU", "slave": "SAE-GR"}],
            "eagle": {"profile": "synthetic-segmented-v1", "url": services[gateway],
                      "server_identity": "urn:transeuroogs:kme:eagle-" + site,
                      "gateway_identity": "urn:transeuroogs:kme:" + site, "gateway_master": "GW-LU", "gateway_slave": "GW-GR",
                      "role": role, "remote_kme_id": "gr" if site == "lu" else "lu",
                      "state_dir": str(root / (site + "-unused-lab-state")), "pki_dir": str(pki["ses"]),
                      "certificate_name": site, "lifetime_seconds": 60},
            "operational": {
                "database": {"dsn_file": str(args.dsn_file), "namespace": str(uuid.uuid4()),
                             "checkpoint_dir": str(root / (site + "-checkpoint")), "wrapping_key_dir": str(keyring), "allow_local_socket": True},
                "crl_files": [str(pki[site] / "ca.crl.pem")], "upstream_crl_files": [str(pki["ses"] / "ca.crl.pem")],
                "limits": {"requests_per_second": 50, "burst": 20, "max_concurrent": 4}},
        }
        peer = "gr" if site == "lu" else "lu"
        pool_id = site.upper() + "/OGS/to-" + peer.upper() + "/final"
        cfg["federation"] = {
            "profile": "transeuroogs-federation-v1", "max_actions": 128,
            "principals": {}, "provider_trust": [], "pools": [{
                "binding": {"pool_id": pool_id, "remote_pool_id": peer.upper() + "/OGS/to-" + site.upper() + "/final",
                            "binding_revision": 1 if site == "lu" else 3, "service_id": "synthetic-LU-GR-final",
                            "service_epoch": "lab-1", "purpose": "application-tls"},
                "domain_id": site.upper(), "ogs_id": "OGS-" + site.upper(), "remote_domain_id": peer.upper(), "remote_ogs_id": "OGS-" + peer.upper(),
                "association": cfg["associations"][0], "provider_identity": cfg["eagle"]["server_identity"],
                "gateway_pair": {"master": "GW-LU", "slave": "GW-GR"}, "mapping_authority": "synthetic-provisioning",
                "contract": {"mode": "synthetic"}, "require_provider_evidence": False, "max_generation_age_seconds": 0}]}
        path = root / (site + ".json"); write(path, cfg)
        commands[site] = [args.binary, "--config", path, "--pki-dir", pki[site], "--certificate-name", site, "--listen", "127.0.0.1:0"]
        subprocess.run(commands[site] + ["--migrate-database"], check=True, stdout=subprocess.DEVNULL)
        urls[site] = "https://" + processes.start(site, commands[site] + ["--initialize-state"])["address"]
        configs[site] = cfg
    app = {}
    for site, role, peer in (("lu", "master", "gr"), ("gr", "slave", "lu")):
        app[site] = {"role": role, "identity": "urn:transeuroogs:kme:" + site, "peer_identity": "urn:transeuroogs:kme:" + peer,
                     "pool": configs[site]["federation"]["pools"][0]["binding"],
                     "master": "SAE-LU", "slave": "SAE-GR", "state_dir": str(root / (site + "-application-state")),
                     "tls": profile(pki["application"], site, "urn:transeuroogs:kme:" + site, True),
                     "kms": dict(profile(pki[site], "sae-" + site, "urn:transeuroogs:kme:" + site), url=urls[site])}
    server_path, client_path = root / "receiver.json", root / "sender.json"
    write(server_path, app["gr"])
    server_command = [sys.executable, ROOT / "src/application/session.py", "--config", server_path, "--port", "0"]
    port = processes.start("receiver", server_command)["port"]
    app["lu"].update(peer_host="localhost", peer_port=port)

    def send():
        write(client_path, app["lu"])
        result = subprocess.run([sys.executable, ROOT / "src/application/session.py", "--config", client_path], capture_output=True, text=True, timeout=20)
        segmented.require(result.returncode == 0, "Authenticated application session failed")
        obj = json.loads(result.stdout)
        segmented.require(obj["state"] == "confirmed", "Application key confirmation missing")
        return obj

    def receipts(result):
        deadline = time.monotonic() + 5
        for site in ("lu", "gr"):
            while True:
                view = session.KMS(app[site]).protection()
                reports = [r for r in view.get("receipts", []) if r["session_id"] == result["session_id"]]
                if {r["status"] for r in reports} == {"confirmed", "retired"}:
                    segmented.require(len(reports) == 2 and all(r["key_id"] == result["key_id"] and r["binding"] == app[site]["pool"] for r in reports), "Receipts lost pool/KID binding")
                    break
                segmented.require(time.monotonic() < deadline, "Confirmed/retired application receipts missing")
                time.sleep(0.05)

    first = send()
    receipts(first)
    # An authenticated application notification replay never retrieves the KID again.
    processes.crash("receiver")
    processes.crash("gr")
    urls["gr"] = "https://" + processes.start("gr", commands["gr"])["address"]
    app["gr"]["kms"]["url"] = urls["gr"]
    write(server_path, app["gr"])
    port = processes.start("receiver", server_command)["port"]
    app["lu"]["peer_port"] = port
    msg = {"version": 2, "pool_context": session.pool_context(app["lu"]), "session_id": first["session_id"], "key_id": first["key_id"], "client": app["lu"]["identity"],
           "server": app["gr"]["identity"], "master": "SAE-LU", "slave": "SAE-GR", "expires": int(time.time()) + 20}
    rejected = False
    with socket.create_connection(("localhost", port), timeout=5) as sock:
        with session.context(app["lu"]["tls"]).wrap_socket(sock, server_hostname="localhost") as stream:
            session.send_frame(stream, msg)
            try:
                session.receive_frame(stream)
            except (session.SessionError, OSError):
                rejected = True
    segmented.require(rejected, "Application replay survived restart")
    # Rotate the wrapping key; the previous generation remains for decryption.
    ring = pathlib.Path(configs["gr"]["operational"]["database"]["wrapping_key_dir"])
    (ring / "v2.key").write_bytes(os.urandom(32)); (ring / "v2.key").chmod(0o600)
    (ring / "active").write_text("v2")
    second = send()
    receipts(first)
    receipts(second)
    segmented.require(first["key_id"] != second["key_id"], "Reused application KID")
    # Wrong peer certificate identity is rejected on the application boundary.
    bad = dict(app["lu"], peer_identity="urn:transeuroogs:kme:wrong")
    # No consuming allocation is needed to test TLS peer pinning itself.
    with socket.create_connection(("localhost", port), timeout=5) as sock:
        with session.context(app["lu"]["tls"]).wrap_socket(sock, server_hostname="localhost") as stream:
            try:
                session.peer_identity(stream, bad["peer_identity"])
                raise RuntimeError("Wrong application peer accepted")
            except session.SessionError:
                pass
    print(json.dumps({"result": "PASS", "postgres_national_kms": 2, "application_sessions_confirmed": 2,
                      "application_mtls": True, "notification_replay_rejected_after_restart": True,
                      "pool_context_authenticated": True, "durable_confirmation_retirement_receipts": True,
                      "wrapping_key_rotation": True, "real_satellite_protocol": False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--emulator", type=pathlib.Path, required=True)
    parser.add_argument("--pki", type=pathlib.Path, required=True)
    parser.add_argument("--dsn-file", type=pathlib.Path, required=True)
    args = parser.parse_args()
    for field in ("binary", "emulator", "pki", "dsn_file"):
        setattr(args, field, getattr(args, field).resolve())
    processes = segmented.Processes()
    with tempfile.TemporaryDirectory(prefix="transeuroogs-operational-") as directory:
        try:
            exercise(args, pathlib.Path(directory), processes)
        finally:
            processes.close()


if __name__ == "__main__":
    main()
