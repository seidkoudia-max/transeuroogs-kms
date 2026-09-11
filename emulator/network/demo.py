"""Separate-process synthetic KMS laboratory: ETSI 020 + trusted mTLS relay.

No key values, certificates or wrapping keys are printed. Temporary state is
encrypted by each KMS. This is not an EAGLE-1 implementation or QKD link cipher.
"""

import argparse
import base64
import http.client
import json
import pathlib
import secrets
import selectors
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def context(pki, name):
    ctx = ssl.create_default_context(cafile=str(pki / "ca.crt.pem"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_flags |= ssl.VERIFY_X509_STRICT
    if name:
        ctx.load_cert_chain(pki / (name + ".crt.pem"), pki / (name + ".key.pem"))
    return ctx


class Lab:
    def __init__(self, binary, pki, directory, direct=False):
        self.binary, self.pki, self.directory = binary, pki, directory
        self.routes = {"lu": ["gr"], "gr": []} if direct else {
            "lu": ["eagle-lu"], "eagle-lu": ["relay-a", "relay-b"],
            "relay-a": ["eagle-gr"], "relay-b": ["eagle-gr"],
            "eagle-gr": ["gr"], "gr": [],
        }
        self.ports, self.sockets, self.processes = {}, {}, {}
        self.summaries = {}
        self.contexts = {name: context(pki, name) for name in ["sae-lu", "sae-gr", "unknown-sae", "lu"]}
        for name in self.routes:
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            self.ports[name] = sock.getsockname()[1]
            self.sockets[name] = sock
        for name, next_nodes in self.routes.items():
            peers = {}
            for target in next_nodes:
                peers[target] = self.peer(name, target, False, direct)
            for source, targets in self.routes.items():
                if name in targets:
                    peers[source] = self.peer(name, source, True, direct)
            config = {
                "kme_id": name, "capacity": 1000,
                "identities": {"urn:transeuroogs:sae:sae-lu": "SAE-LU", "urn:transeuroogs:sae:sae-gr": "SAE-GR"},
                "associations": [{"master": "SAE-LU", "slave": "SAE-GR"}],
                "inter_kms": {
                    "public_url": self.url(name), "identity": "urn:transeuroogs:kme:" + name,
                    "state_dir": str(directory / (name + "-state")),
                    "local_saes": ["SAE-LU"] if name == "lu" else (["SAE-GR"] if name == "gr" else []),
                    "peers": peers, "routes": {"SAE-GR": next_nodes} if next_nodes else {},
                    "target_kmes": {"SAE-GR": "gr"},
                },
            }
            (directory / (name + ".json")).write_text(json.dumps(config, indent=2) + "\n")

    def url(self, name):
        return "https://127.0.0.1:" + str(self.ports[name])

    def peer(self, name, target, incoming, direct):
        mode = "etsi020" if direct or "lu" in (name, target) or "gr" in (name, target) else "lab-relay"
        return {"url": self.url(target), "identity": "urn:transeuroogs:kme:" + target, "mode": mode, "incoming": incoming}

    def start(self, name, count=0):
        if name in self.sockets:
            self.sockets.pop(name).close()
        process = subprocess.Popen([
            str(self.binary), "--config", str(self.directory / (name + ".json")),
            "--pki-dir", str(self.pki), "--certificate-name", name,
            "--listen", "127.0.0.1:" + str(self.ports[name]),
            "--synthetic-keys", str(count), "--lab-summary",
        ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.processes[name] = process
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            require(bool(selector.select(timeout=10)), "Node startup timed out: " + name)
        line = process.stdout.readline()
        require(bool(line), "Node failed to start: " + name)
        require(json.loads(line).get("event") == "listening", "Node readiness missing: " + name)

    def stop(self, name):
        process = self.processes.pop(name, None)
        if process is None:
            return
        process.terminate()
        try:
            output, _ = process.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise RuntimeError("Node did not shut down: " + name) from None
        require(process.returncode == 0, "Node exited unsuccessfully: " + name)
        for line in output.splitlines():
            event = json.loads(line)
            if event.get("event") == "network_summary":
                self.summaries[name] = event["summary"]

    def crash(self, name):
        process = self.processes.pop(name)
        process.kill()
        process.communicate(timeout=5)

    def close(self):
        try:
            for name in list(self.processes):
                self.stop(name)
        finally:
            for process in self.processes.values():
                process.kill()
                process.wait()
            for sock in self.sockets.values():
                sock.close()

    def call(self, name, identity, path, body=None):
        conn = http.client.HTTPSConnection("127.0.0.1", self.ports[name], context=self.contexts[identity], timeout=5)
        try:
            conn.connect()
            uris = [v for k, v in conn.sock.getpeercert().get("subjectAltName", ()) if k == "URI"]
            require(uris == ["urn:transeuroogs:kme:" + name], "Server identity mismatch")
            conn.request("GET" if body is None else "POST", path, body=None if body is None else json.dumps(body), headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            data = response.read(1024 * 1024)
            require(response.getheader("Cache-Control") == "no-store", "Response permits caching")
            return response.status, json.loads(data) if data else None
        finally:
            conn.close()

    def ready(self, count):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            code, data = self.call("lu", "sae-lu", "/api/v1/keys/SAE-GR/status")
            require(code == 200 and data["target_KME_ID"] == "gr", "Incorrect remote KME status")
            if data["stored_key_count"] == count:
                return
            time.sleep(0.1)  # Only read-only status is polled, never SAE delivery.
        raise RuntimeError("End-to-end acknowledgements did not complete")

    def deliver(self, count):
        code, first = self.call("lu", "sae-lu", "/api/v1/keys/SAE-GR/enc_keys", {"number": count, "size": 256})
        require(code == 200 and len(first["keys"]) == count, "Source delivery failed")
        ids = [{"key_ID": k["key_ID"]} for k in first["keys"]]
        require(len({x["key_ID"] for x in ids}) == count, "Duplicate IDs")
        code, second = self.call("gr", "sae-gr", "/api/v1/keys/SAE-LU/dec_keys", {"key_IDs": ids})
        require(code == 200 and len(second["keys"]) == count, "Destination delivery failed")
        for a, b in zip(first["keys"], second["keys"]):
            require(uuid.UUID(a["key_ID"]).version == 4, "Invalid UUID")
            require(len(base64.b64decode(a["key"], validate=True)) == 32, "Wrong key size")
            require(a["key_ID"] == b["key_ID"] and secrets.compare_digest(a["key"], b["key"]), "Key mismatch")
        return ids


def scenario(args, direct=False, failed_path=False):
    with tempfile.TemporaryDirectory(prefix="transeuroogs-network-") as temp:
        lab = Lab(args.binary.resolve(), args.pki.resolve(), pathlib.Path(temp), direct)
        count = 4 if direct else (8 if failed_path else 24)
        try:
            # Downstream nodes first; each process owns an independent journal.
            for name in reversed(list(lab.routes)):
                if name != "lu" and not (failed_path and name == "relay-a"):
                    lab.start(name)
            lab.start("lu", count)
            lab.ready(count)
            for name in ("lu", "gr"):
                lab.crash(name)
                lab.start(name)  # Ready material survives SIGKILL without shutdown hooks.
            lab.ready(count)
            for node, identity in [("lu", "sae-gr"), ("gr", "sae-lu"), ("lu", "lu")]:
                code, _ = lab.call(node, identity, "/api/v1/keys/SAE-GR/status")
                require(code == 401, "SAE/KME role isolation failed")
            ids = lab.deliver(count)
            for name in ("lu", "gr"):
                lab.stop(name)
                lab.start(name)
            code, _ = lab.call("gr", "sae-gr", "/api/v1/keys/SAE-LU/dec_keys", {"key_IDs": ids})
            require(code == 503, "Restart revived consumed destination keys")
            code, _ = lab.call("lu", "sae-lu", "/api/v1/keys/SAE-GR/enc_keys", {"number": 1})
            require(code == 503, "Restart revived consumed source keys")
        finally:
            lab.close()
        if not direct:
            paths = lab.summaries["eagle-lu"]["Paths"]
            expected = {"relay-b": count} if failed_path else {"relay-a": count // 2, "relay-b": count // 2}
            require(paths == expected, "Unexpected multipath distribution or failover")
        print(json.dumps({"result": "PASS", "scenario": "direct-etsi020" if direct else ("preflight-failover" if failed_path else "multipath-hop-by-hop"), "synthetic_keys_verified": count, "restart_replay_rejected": True, "paths": {} if direct else paths}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--pki", type=pathlib.Path, required=True)
    args = parser.parse_args()
    scenario(args, direct=True)
    scenario(args)
    scenario(args, failed_path=True)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, http.client.HTTPException) as exc:
        detail = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
        print("Network laboratory failed: " + detail + ". No key data displayed.", file=sys.stderr)
        sys.exit(1)
