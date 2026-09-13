"""Two independent synthetic KMS processes: services, adapters and orchestration."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from load_tfs_driver import load_driver
Driver = load_driver()
from teraflow.client import Client, ManagementError
from teraflow.QKDDriver import ALLOCATION, STATE, CHANGES
from teraflow.adapter import SyntheticAdapter
from teraflow.orchestrator import Orchestrator, Incomplete
spec = importlib.util.spec_from_file_location("sae_services", ROOT / "emulator/sae/demo.py")
sae = importlib.util.module_from_spec(spec); spec.loader.exec_module(sae)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "pki-binary", "metadata-binary", "node-output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="transeuroogs-services-") as directory:
        root = Path(directory); nodes = {}; processes = []
        actor = "urn:transeuroogs:sae:controller-sae"
        adapter = "urn:transeuroogs:sae:unknown-sae"
        rule = {"paused": False, "allowed_sources": ["synthetic"], "allowed_issuers": [], "require_evidence": True,
                "allow_satellite": False, "max_generation_age_seconds": 3600, "max_local_age_seconds": 600, "max_keys_per_request": 4}

        def start(node, count):
            process = subprocess.Popen([str(args.binary.resolve()), "--config", str(node["config"]), "--pki-dir", str(node["pki"]),
                                        "--listen", "127.0.0.1:0", "--synthetic-keys", str(count)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            processes.append(process)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                sae.require(bool(selector.select(10)), "Service KMS startup timed out")
            line = process.stdout.readline(); sae.require(bool(line), "Service KMS startup failed")
            port = int(json.loads(line)["address"].rsplit(":", 1)[1])
            node["process"], node["base"] = process, "https://127.0.0.1:" + str(port)
            def settings(name):
                return {"ca_file": str(node["pki"] / "ca.crt.pem"), "cert_file": str(node["pki"] / (name + ".crt.pem")),
                        "key_file": str(node["pki"] / (name + ".key.pem")), "server_identity": "urn:transeuroogs:kme:LU-KMS"}
            node["driver"] = Driver("127.0.0.1", port, **settings("controller-sae"))
            node["adapter"] = SyntheticAdapter(Client("127.0.0.1", port, **settings("unknown-sae")))

        def stop(node):
            process = node["process"]; process.terminate()
            try:
                process.wait(7)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
            process.stdout.close(); processes.remove(process)

        try:
            for name in ("qci-a", "qci-b"):
                path = root / name; path.mkdir(); pki = path / "pki"
                subprocess.run([str(args.pki_binary.resolve()), "--out", str(pki)], check=True, capture_output=True)
                subprocess.run([str(args.metadata_binary.resolve()), "keygen", "--private", str(path / "sign.pem"), "--public", str(path / "public.pem")], check=True, capture_output=True)
                config = json.loads((ROOT / "deploy/config/local.json").read_text()); pair = config["associations"][0]
                app_id, remote, link_id = [str(uuid.uuid4()) for _ in range(3)]
                config["metadata"] = {"domain": name, "issuer": "urn:transeuroogs:kme:LU-KMS", "namespace": name,
                                      "credential_id": "synthetic", "signing_key_file": str(path / "sign.pem"), "state_dir": str(path / "state"),
                                      "max_events": 1000, "clock_uncertainty_ms": 0, "readers": {"urn:test:investigator": [pair]}}
                config["sdn"] = {"node_id": str(uuid.uuid4()), "location": "synthetic " + name, "max_commands": 100,
                                 "applications": [{"app_id": app_id, "association": pair, "remote_node_id": remote, "rule": rule}],
                                 "principals": {actor: {"associations": [pair], "write": True, "services": True},
                                                adapter: {"associations": [pair], "telemetry": True}},
                                 "services": {"links": [{"link_id": link_id, "association": pair, "local_interface": 1, "remote_interface": 2,
                                                          "remote_node_id": remote, "model": "synthetic control adapter", "technology": "DV-QKD",
                                                          "adapter_identity": adapter, "mode": "synthetic", "observation_ttl_seconds": 600}]}}
                cfg = path / "config.json"; cfg.write_text(json.dumps(config))
                node = nodes[name] = {"config": cfg, "pki": pki, "pair": pair, "link": link_id, "app": app_id}
                start(node, 4); driver = node["driver"]
                code, _ = sae.call(node["base"], sae.context(pki, "sae-lu"), "GET", "/api/v1/keys/SAE-GR/enc_keys")
                sae.require(code == 503, "Unregistered service consumed keys")
                command = {"command_id": str(uuid.uuid4()), "expected_revision": 0, "association": pair,
                           "service": {"operation": "link_create", "resource_id": link_id, "enabled": True}}
                sae.require(driver.SetConfig([(ALLOCATION, command)]) == [True], "Link intent failed")
                sae.require("qkdl_status" not in driver.client.node()["qkd_links"]["qkd_link"][0], "Unacknowledged link appears operational")
                report = node["adapter"].observe(link_id)
                forged = copy.deepcopy(report["command"]); forged["command_id"] = str(uuid.uuid4()); forged["expected_revision"] = 2
                result = driver.SetConfig([(ALLOCATION, forged)])[0]
                sae.require(isinstance(result, ManagementError) and result.status == 403, "Controller forged adapter telemetry")
                sae.require(len(driver.GetConfig(["__links__", "__interfaces__"])) == 2, "TFS link/interface discovery failed")
            desired = {}
            for name, node in nodes.items():
                state = node["driver"].client.state()
                desired[name] = {"node_id": state["node_id"], "pool": state["applications"][0].get("pool", {}), "association": node["pair"], "rule": rule,
                                 "service": {"operation": "application_create", "resource_id": node["app"], "ttl": 600, "backing_links": [node["link"]]}}
            class LostActivation:
                def __init__(self, driver): self.driver, self.lose = driver, True
                def GetConfig(self, keys): return self.driver.GetConfig(keys)
                def SetConfig(self, resources):
                    result = self.driver.SetConfig(resources)
                    if self.lose and resources[0][1].get("rule", {}).get("paused") is False:
                        self.lose = False; return [ManagementError()]
                    return result
            drivers = {name: node["driver"] for name, node in nodes.items()}; drivers["qci-b"] = LostActivation(drivers["qci-b"])
            journal = root / "workflow.json"
            try:
                Orchestrator(drivers, journal).run(desired)
            except Incomplete:
                sae.require(json.loads(journal.read_text())["status"] == "partial_activation", "Uncertain activation not identified")
            else:
                raise RuntimeError("Lost activation reply not reported")
            # Independent process restarts without reseeding. Retry exact IDs.
            for name, node in nodes.items(): stop(node); start(node, 0)
            drivers = {name: node["driver"] for name, node in nodes.items()}
            job = Orchestrator(drivers, journal).run(desired)
            sae.require(job["status"] == "complete", "Workflow recovery failed")
            for node in nodes.values():
                driver = node["driver"]
                sae.require(driver.client.state()["revision"] == 6, "Recovery repeated a state transition")
                sae.require(driver.SubscribeState([(STATE, 10, 1), (CHANGES, 10, 1)]) == [True, True], "TFS monitoring subscription failed")
                samples = list(driver.GetState())
                sae.require(len(samples) == 2 and all(isinstance(s[2], dict) for s in samples), "TFS monitoring samples unavailable")
                page = driver.client.changes(4); sae.require(page["next_revision"] == 6, "Durable cursor replay failed")
                code, first = sae.call(node["base"], sae.context(node["pki"], "sae-lu"), "GET", "/api/v1/keys/SAE-GR/enc_keys")
                sae.require(code == 200, "Activated service cannot allocate")
                ids = [{"key_ID": k["key_ID"]} for k in first["keys"]]
                code, second = sae.call(node["base"], sae.context(node["pki"], "sae-gr"), "POST", "/api/v1/keys/SAE-LU/dec_keys", {"key_IDs": ids})
                sae.require(code == 200 and first == second, "Local pair mismatch")
                del first, second
            args.node_output.parent.mkdir(parents=True, exist_ok=True)
            args.node_output.write_text(json.dumps({"etsi-qkd-sdn-node:qkd_node": nodes["qci-a"]["driver"].client.node()}))
            left = nodes["qci-a"]["driver"]; stricter = dict(rule, max_keys_per_request=1)
            left.client.apply({"command_id": str(uuid.uuid4()), "expected_revision": 6, "association": nodes["qci-a"]["pair"], "rule": stricter})
            result = Orchestrator(drivers, journal).abort()
            sae.require(result["status"] == "aborted", "Workflow abort failed")
            for node in nodes.values():
                code, _ = sae.call(node["base"], sae.context(node["pki"], "sae-lu"), "GET", "/api/v1/keys/SAE-GR/enc_keys")
                sae.require(code == 503, "Abort failed to pause delivery")
            sae.require(left.client.state()["applications"][0]["rule"]["max_keys_per_request"] == 1, "Abort overwrote newer policy")
            print(json.dumps({"result": "PASS", "independent_kms_processes": 2, "physical_devices": False, "full_tfs_cluster": False,
                              "synthetic_adapter_ack": True, "lifecycle_restart": True, "lost_activation_recovery": True, "abort_preserves_new_policy": True}))
        finally:
            for process in processes:
                process.terminate()
                try: process.wait(7)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
                process.stdout.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("Service acceptance failed: " + (str(exc) if isinstance(exc, (RuntimeError, ManagementError)) else type(exc).__name__), file=sys.stderr)
        raise SystemExit(1) from None
