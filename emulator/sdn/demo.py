"""Synthetic KMS + actual TFS driver-contract acceptance over verified mTLS."""
import argparse
import concurrent.futures
import importlib.util
import json
import pathlib
import selectors
import subprocess
import sys
import tempfile
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from load_tfs_driver import load_driver

spec = importlib.util.spec_from_file_location("sae_lab", ROOT / "emulator/sae/demo.py")
sae = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sae)
Driver = load_driver()
from teraflow.client import Client, ManagementError
from teraflow.QKDDriver import ALLOCATION, STATE
from teraflow.policy import Reconciler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--pki-binary", type=pathlib.Path, required=True)
    parser.add_argument("--metadata-binary", type=pathlib.Path, required=True)
    parser.add_argument("--node-output", type=pathlib.Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="transeuroogs-sdn-") as tmp:
        directory = pathlib.Path(tmp); pki = directory / "pki"
        subprocess.run([str(args.pki_binary.resolve()), "--out", str(pki)], check=True, capture_output=True)
        subprocess.run([str(args.metadata_binary.resolve()), "keygen", "--private", str(directory / "sign.key.pem"), "--public", str(directory / "sign.pub.pem")], check=True, capture_output=True)
        config = json.loads((ROOT / "deploy/config/local.json").read_text())
        pair = config["associations"][0]
        actor = "urn:transeuroogs:sae:controller-sae"
        config["metadata"] = {"domain": "LU", "issuer": "urn:transeuroogs:kme:LU-KMS", "namespace": "sdn-lab", "credential_id": "lab", "signing_key_file": str(directory / "sign.key.pem"), "state_dir": str(directory / "state"), "max_events": 1000, "clock_uncertainty_ms": 0, "readers": {"urn:transeuroogs:sae:unknown-sae": [pair]}}
        rule = {"paused": False, "allowed_sources": ["synthetic"], "allowed_issuers": [config["metadata"]["issuer"]], "require_evidence": True, "allow_satellite": False, "max_generation_age_seconds": 3600, "max_local_age_seconds": 600, "max_keys_per_request": 16}
        config["sdn"] = {"node_id": str(uuid.uuid4()), "location": "synthetic LU lab", "max_commands": 100,
                         "applications": [{"app_id": str(uuid.uuid4()), "remote_node_id": str(uuid.uuid4()), "association": pair, "rule": rule}], "principals": {actor: {"associations": [pair], "write": True, "routes": False}}}
        cfg = directory / "config.json"; cfg.write_text(json.dumps(config))
        process = None

        def stop():
            nonlocal process
            if process:
                process.terminate()
                try:
                    process.wait(timeout=7)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
                process.stdout.close(); process = None

        def start(count):
            nonlocal process
            process = subprocess.Popen([str(args.binary.resolve()), "--config", str(cfg), "--pki-dir", str(pki), "--listen", "127.0.0.1:0", "--synthetic-keys", str(count)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                sae.require(bool(selector.select(timeout=10)), "SDN KMS startup timed out")
            line = process.stdout.readline(); sae.require(bool(line), "SDN KMS startup failed")
            ready = json.loads(line); sae.require(ready.get("event") == "listening", "No readiness")
            port = int(ready["address"].rsplit(":", 1)[1])
            return port, "https://127.0.0.1:" + str(port)

        def settings(name="controller-sae"):
            return {"ca_file": str(pki / "ca.crt.pem"), "cert_file": str(pki / (name + ".crt.pem")), "key_file": str(pki / (name + ".key.pem")), "server_identity": config["metadata"]["issuer"]}

        try:
            port, base = start(8)
            driver = Driver("127.0.0.1", port, **settings())
            sae.require(driver.Connect(), "TFS driver could not authenticate")
            state = driver.GetConfig([STATE])[0][1]
            sae.require(state["applications"][0]["counts"]["eligible"] == 8, "Wrong eligible inventory")
            node = driver.client.node()
            if args.node_output:
                args.node_output.parent.mkdir(parents=True, exist_ok=True)
                args.node_output.write_text(json.dumps({"etsi-qkd-sdn-node:qkd_node": node}))
            sae.require(len(driver.GetConfig(["__apps__"])) == 1, "Application discovery failed")
            sae.require(isinstance(driver.SetConfig([("/link", {})])[0], NotImplementedError), "Unsupported provisioning succeeded")
            sae.require(driver.SubscribeState([(STATE, 10, 1)]) == [True], "Snapshot subscription failed")
            sae.require(len(list(driver.GetState())) == 1, "Subscribed snapshot unavailable")
            master, slave = sae.context(pki, "sae-lu"), sae.context(pki, "sae-gr")
            for name in ("sae-lu", "unknown-sae"):
                denied = Driver("127.0.0.1", port, **settings(name))
                sae.require(not denied.Connect(), "Application/investigator obtained controller access")
            wrong = settings(); wrong["server_identity"] = "urn:transeuroogs:kme:wrong"
            sae.require(not Driver("127.0.0.1", port, **wrong).Connect(), "Wrong KMS identity accepted")
            code, _ = sae.call(base, sae.context(pki, "controller-sae"), "GET", "/api/v1/keys/SAE-GR/enc_keys")
            sae.require(code == 401, "Controller retrieved key material")
            code, _ = sae.call(base, sae.context(pki, "controller-sae"), "GET", "/metadata/v1/events")
            sae.require(code == 401, "Controller obtained investigator history")
            paused = dict(rule, paused=True)
            command = {"command_id": str(uuid.uuid4()), "expected_revision": 0, "association": pair, "rule": paused}
            # The same request races on independent TLS connections; one state
            # transition and one signed command event must result.
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
                results = list(workers.map(lambda _: driver.SetConfig([(ALLOCATION, command)])[0], range(8)))
            sae.require(all(x is True for x in results), "Concurrent idempotent command failed")
            sae.require(driver.client.state()["revision"] == 1, "Replay advanced revision")
            code, _ = sae.call(base, master, "GET", "/api/v1/keys/SAE-GR/enc_keys")
            sae.require(code == 503, "Paused allocation delivered")
            stop(); port, base = start(0)
            driver = Driver("127.0.0.1", port, **settings())
            sae.require(driver.SetConfig([(ALLOCATION, command)])[0] is True, "Command replay failed after restart")
            code, _ = sae.call(base, master, "GET", "/api/v1/keys/SAE-GR/enc_keys")
            sae.require(code == 503, "Restart lost local policy")
            class LostReply:
                lose = True
                def GetConfig(self, keys):
                    return driver.GetConfig(keys)
                def SetConfig(self, resources):
                    result = driver.SetConfig(resources)
                    if self.lose:
                        self.lose = False
                        return [ManagementError()]
                    return result
            desired = {"association": pair, "rule": rule}
            outbox = directory / "pending-policy.json"
            reconciler = Reconciler(LostReply(), outbox)
            try:
                reconciler.reconcile(desired)
            except RuntimeError:
                sae.require(outbox.exists(), "Lost reply discarded pending command")
            else:
                raise RuntimeError("Lost policy reply not reported")
            result = reconciler.reconcile(desired)
            sae.require(result["revision"] == 2 and not outbox.exists(), "Exact pending command replay failed")
            sae.require(not reconciler.reconcile(desired)["changed"], "Converged policy generated a command")
            # Stop consulting the controller and complete a key-plane delivery.
            driver.Disconnect()
            code, first = sae.call(base, master, "POST", "/api/v1/keys/SAE-GR/enc_keys", {"number": 2, "size": 256})
            sae.require(code == 200, "KMS depended on live controller")
            ids = [{"key_ID": k["key_ID"]} for k in first["keys"]]
            code, second = sae.call(base, slave, "POST", "/api/v1/keys/SAE-LU/dec_keys", {"key_IDs": ids})
            sae.require(code == 200 and first == second, "Pair delivery mismatch")
            del first, second
            code, _ = sae.call(base, slave, "POST", "/api/v1/keys/SAE-LU/dec_keys", {"key_IDs": ids})
            sae.require(code == 503, "Key replay accepted")
            code, events = sae.call(base, sae.context(pki, "unknown-sae"), "GET", "/metadata/v1/events")
            sae.require(code == 200 and sum("control" in e["event"] for e in events["page"]["events"]) == 2, "Command history incomplete or duplicated")
            print(json.dumps({"result":"PASS", "tfs_v7_driver_contract":True, "full_tfs_cluster":False, "policy_restart_replay":True, "controller_key_isolation":True, "controller_outage_delivery":True, "signed_policy_events":2}))
        finally:
            stop()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        detail = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
        print("SDN acceptance failed: " + detail + "; no key data displayed.", file=sys.stderr)
        raise SystemExit(1) from None
