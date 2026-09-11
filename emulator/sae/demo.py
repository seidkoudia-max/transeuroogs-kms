"""Synthetic two-SAE HTTPS laboratory. Never prints key values or certificates."""

import argparse
import base64
import http.client
import json
import pathlib
import secrets
import selectors
import ssl
import subprocess
import sys
import time
import urllib.parse
import uuid


def context(pki, identity):
    ctx = ssl.create_default_context(cafile=str(pki / "ca.crt.pem"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if identity:
        ctx.load_cert_chain(pki / f"{identity}.crt.pem", pki / f"{identity}.key.pem")
    return ctx


def call(base, ctx, method, path, body=None):
    target = urllib.parse.urlparse(base)
    if target.scheme != "https" or not target.hostname:
        raise RuntimeError("The laboratory requires an HTTPS endpoint")
    conn = http.client.HTTPSConnection(target.hostname, target.port, context=ctx, timeout=5)
    try:
        conn.connect()
        identities = [v for k, v in conn.sock.getpeercert().get("subjectAltName", ()) if k == "URI"]
        if identities != ["urn:transeuroogs:kme:LU-KMS"]:
            raise RuntimeError("KME certificate identity mismatch")
        headers = {"Content-Type": "application/json"}
        conn.request(method, path, body=None if body is None else json.dumps(body), headers=headers)
        response = conn.getresponse()
        data = response.read(1024 * 1024)
        if response.getheader("Cache-Control") != "no-store":
            raise RuntimeError("KMS response permits caching")
        return response.status, json.loads(data)
    finally:
        conn.close()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def exercise(base, pki, count, wait):
    master, slave = context(pki, "sae-lu"), context(pki, "sae-gr")
    deadline = time.monotonic() + wait
    while True:
        try:
            status, inventory = call(base, master, "GET", "/api/v1/keys/SAE-GR/status")
            require(status == 200, "Status request failed")
            break
        except (OSError, http.client.HTTPException):
            if time.monotonic() >= deadline:
                raise RuntimeError("KMS did not become ready") from None
            time.sleep(0.25)  # Only read-only status is retried; deliveries never are.
    require(inventory["stored_key_count"] == count, "Unexpected initial inventory")
    require(inventory["source_KME_ID"] == "LU-KMS", "Unexpected source KME")
    try:
        call(base, context(pki, None), "GET", "/api/v1/keys/SAE-GR/status")
    except (OSError, http.client.HTTPException):
        pass
    else:
        raise RuntimeError("Unauthenticated TLS connection was accepted")
    code, _ = call(base, context(pki, "unknown-sae"), "GET", "/api/v1/keys/SAE-GR/status")
    require(code == 401, "Unknown SAE was accepted")
    code, _ = call(base, master, "GET", "/api/v1/keys/OTHER/enc_keys")
    require(code == 401, "Unauthorized association was accepted")

    seen, completed, last_id = set(), 0, None
    while completed < count:
        batch = min(128, count - completed)
        code, first = call(base, master, "POST", "/api/v1/keys/SAE-GR/enc_keys", {"number": batch, "size": 256})
        require(code == 200 and len(first["keys"]) == batch, "Master delivery failed")
        ids = []
        for key in first["keys"]:
            key_id = key["key_ID"]
            require(str(uuid.UUID(key_id)) == key_id and uuid.UUID(key_id).version == 4, "Invalid key ID")
            require(key_id not in seen, "Key ID was reused")
            require(len(base64.b64decode(key["key"], validate=True)) == 32, "Unexpected key size")
            seen.add(key_id)
            ids.append({"key_ID": key_id})
        code, second = call(base, slave, "POST", "/api/v1/keys/SAE-LU/dec_keys", {"key_IDs": ids})
        require(code == 200 and len(second["keys"]) == batch, "Slave delivery failed")
        for a, b in zip(first["keys"], second["keys"]):
            require(a["key_ID"] == b["key_ID"] and secrets.compare_digest(a["key"], b["key"]), "Corresponding deliveries differ")
        last_id = ids[-1]["key_ID"]
        completed += batch
    code, _ = call(base, slave, "GET", "/api/v1/keys/SAE-LU/dec_keys?key_ID=" + last_id)
    require(code == 503, "Consumed slave key was delivered again")
    code, _ = call(base, master, "GET", "/api/v1/keys/SAE-GR/enc_keys")
    require(code == 503, "Exhausted pool delivered a key")
    code, inventory = call(base, master, "GET", "/api/v1/keys/SAE-GR/status")
    require(code == 200 and inventory["stored_key_count"] == 0, "Pool did not deplete")
    print(json.dumps({"result": "PASS", "synthetic_keys_verified": completed, "unique_key_ids": len(seen), "matching_sae_deliveries": True, "replay_rejected": True, "mtls_enforced": True, "remaining_keys": 0}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--binary", type=pathlib.Path)
    source.add_argument("--url")
    parser.add_argument("--pki", type=pathlib.Path, default=pathlib.Path(".local/pki"))
    parser.add_argument("--config", type=pathlib.Path, default=pathlib.Path("deploy/config/local.json"))
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--wait", type=float, default=30)
    args = parser.parse_args()
    require(1 <= args.count <= 100000, "Count must be between 1 and 100000")
    process = None
    try:
        base = args.url
        if args.binary:
            process = subprocess.Popen([str(args.binary.resolve()), "--config", str(args.config.resolve()), "--pki-dir", str(args.pki.resolve()), "--listen", "127.0.0.1:0", "--synthetic-keys", str(args.count)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                require(bool(selector.select(timeout=10)), "KMS startup timed out")
            line = process.stdout.readline()
            require(bool(line), "KMS failed to start; check configuration and test certificates")
            ready = json.loads(line)
            require(ready.get("event") == "listening", "KMS did not report readiness")
            base = "https://" + ready["address"]
        exercise(base, args.pki, args.count, args.wait)
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=7)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            process.stdout.close()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, http.client.HTTPException) as exc:
        print(f"Laboratory failed ({type(exc).__name__}); no key data displayed.", file=sys.stderr)
        sys.exit(1)
