"""Reference SAE integration: authenticated KID notification and TLS 1.3 PSK.

The outer mutually authenticated TLS stream carries metadata and the inner TLS
stream. OpenSSL performs both handshakes; no key-confirmation primitive is
implemented here. Only synthetic key sources are supported by the project.
Requires Python 3.13+ with ssl.HAS_PSK.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
import pathlib
import socket
import sqlite3
import ssl
import struct
import threading
import time
import urllib.parse
import uuid

MAX_FRAME = 16384
ALPN = "transeuroogs-sae/1"


class SessionError(Exception):
    """A redacted failure; the application must start with a fresh key."""


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise SessionError("duplicate field")
        result[name] = value
    return result


def decode(data):
    if len(data) > MAX_FRAME:
        raise SessionError("oversized message")
    try:
        return json.loads(data, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise SessionError("invalid message") from None


def identifier(value):
    try:
        parsed = uuid.UUID(value)
        return parsed.version == 4 and str(parsed) == value
    except (ValueError, AttributeError, TypeError):
        return False


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def read_exact(stream, size):
    chunks = bytearray()
    while len(chunks) < size:
        data = stream.recv(size - len(chunks))
        if not data:
            raise SessionError("connection lost")
        chunks.extend(data)
    return bytes(chunks)


def send_frame(stream, value):
    data = encode(value)
    if len(data) > MAX_FRAME:
        raise SessionError("oversized message")
    stream.sendall(struct.pack("!I", len(data)) + data)


def receive_frame(stream):
    size = struct.unpack("!I", read_exact(stream, 4))[0]
    if size > MAX_FRAME:
        raise SessionError("oversized message")
    return decode(read_exact(stream, size))


def private_file(path):
    p = pathlib.Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_mode & 0o777 != 0o600:
        raise SessionError("private file permissions")


def context(profile, server=False):
    """Fresh context on every connection: current certificates and full CRLs."""
    private_file(profile["key"])
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    c.minimum_version = c.maximum_version = ssl.TLSVersion.TLSv1_3
    c.verify_mode = ssl.CERT_REQUIRED
    c.load_verify_locations(cafile=profile["ca"])
    for crl in profile["crls"]:
        c.load_verify_locations(cafile=crl)
    if not profile["crls"]:
        raise SessionError("CRLs required")
    c.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN | ssl.VERIFY_X509_STRICT
    c.load_cert_chain(profile["cert"], profile["key"])
    c.set_alpn_protocols([ALPN] if profile.get("application") else ["http/1.1"])
    c.options |= ssl.OP_NO_TICKET
    if server:
        c.num_tickets = 0
    # Constructing SSLContext directly never enables SSLKEYLOGFILE logging.
    return c


def peer_identity(stream, expected):
    uris = [value for typ, value in stream.getpeercert().get("subjectAltName", []) if typ == "URI"]
    if uris != [expected]:
        raise SessionError("peer identity rejected")


class KMS:
    def __init__(self, config):
        self.config = config

    def _request(self, peer, operation, body):
        p = self.config["kms"]
        url = urllib.parse.urlsplit(p["url"])
        if url.scheme != "https" or not url.hostname or url.path or url.query or url.fragment or url.username:
            raise SessionError("invalid KMS endpoint")
        conn = http.client.HTTPSConnection(url.hostname, url.port or 443, timeout=5, context=context(p))
        try:
            conn.connect()
            peer_identity(conn.sock, p["identity"])
            conn.request("POST", "/api/v1/keys/" + urllib.parse.quote(peer, safe="") + "/" + operation,
                         body=encode(body), headers={"Content-Type": "application/json", "Connection": "close"})
            response = conn.getresponse()
            raw = response.read(MAX_FRAME + 1)
            if response.status != 200 or response.getheader("Content-Type", "").split(";")[0] != "application/json":
                raise SessionError("key unavailable")
            data = decode(raw)
            if not isinstance(data, dict) or set(data) != {"keys"} or len(data["keys"]) != 1:
                raise SessionError("invalid key response")
            key = data["keys"][0]
            if set(key) != {"key_ID", "key"} or not identifier(key["key_ID"]):
                raise SessionError("invalid key response")
            material = base64.b64decode(key["key"], validate=True)
            if len(material) != 32 or base64.b64encode(material).decode() != key["key"]:
                raise SessionError("invalid key size")
            return key["key_ID"], bytearray(material)
        except (OSError, ValueError, TypeError, KeyError, http.client.HTTPException):
            raise SessionError("key request failed; do not retry") from None
        finally:
            conn.close()

    def protection(self, path="state", body=None):
        """Material-free project endpoint; receipt POSTs are idempotent."""
        p = self.config["kms"]
        url = urllib.parse.urlsplit(p["url"])
        if url.scheme != "https" or not url.hostname or url.path or url.query or url.fragment or url.username:
            raise SessionError("invalid KMS endpoint")
        conn = http.client.HTTPSConnection(url.hostname, url.port or 443, timeout=5, context=context(p))
        try:
            conn.connect()
            peer_identity(conn.sock, p["identity"])
            conn.request("GET" if body is None else "POST", "/federation/v1/" + path,
                         body=None if body is None else encode(body), headers={"Content-Type": "application/json", "Connection": "close"})
            response = conn.getresponse()
            raw = response.read(MAX_FRAME + 1)
            if path == "receipts" and response.status == 204:
                return None
            if path == "state" and response.status == 200:
                return decode(raw)
            raise SessionError("protection service unavailable")
        except (OSError, ValueError, TypeError, KeyError, http.client.HTTPException):
            raise SessionError("protection request failed") from None
        finally:
            conn.close()

    def allocate(self):
        return self._request(self.config["slave"], "enc_keys", {"number": 1, "size": 256})

    def retrieve(self, kid):
        returned, key = self._request(self.config["master"], "dec_keys", {"key_IDs": [{"key_ID": kid}]})
        if returned != kid:
            key[:] = bytes(len(key))
            raise SessionError("mismatched key ID")
        return key


class Ledger:
    """Metadata only; commit an attempt before every consuming KMS operation."""
    def __init__(self, directory, binding, capacity=100000):
        p = pathlib.Path(directory)
        p.mkdir(mode=0o700, parents=True, exist_ok=True)
        if p.is_symlink() or p.stat().st_mode & 0o777 != 0o700:
            raise SessionError("state directory permissions")
        path = p / "sessions.sqlite"
        if path.exists():
            private_file(path)
        else:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        self.db = sqlite3.connect(path, timeout=5, check_same_thread=False)
        self.lock = threading.Lock()
        self.capacity = capacity
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS binding (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, kid TEXT UNIQUE, state TEXT NOT NULL, expires INTEGER NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS receipts (id TEXT PRIMARY KEY, sid TEXT NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL, sent INTEGER NOT NULL DEFAULT 0, UNIQUE(sid,status))")
        row = self.db.execute("SELECT value FROM binding WHERE id=1").fetchone()
        value = hashlib.sha256(encode(binding)).hexdigest()
        if row and row[0] != value:
            self.db.close()
            raise SessionError("state binding changed")
        self.db.execute("INSERT OR IGNORE INTO binding VALUES(1,?)", (value,))
        self.db.commit()

    def begin(self, sid, kid, expires):
        if not identifier(sid) or (kid is not None and not identifier(kid)):
            raise SessionError("invalid session")
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if self.db.execute("SELECT count(*) FROM sessions").fetchone()[0] >= self.capacity:
                raise SessionError("session capacity reached")
            try:
                self.db.execute("INSERT INTO sessions VALUES(?,?,'uncertain',?)", (sid, kid, expires))
            except sqlite3.IntegrityError:
                raise SessionError("session or key already used") from None

    def bind(self, sid, kid):
        with self.lock, self.db:
            try:
                changed = self.db.execute("UPDATE sessions SET kid=? WHERE sid=? AND kid IS NULL AND state='uncertain'", (kid, sid)).rowcount
                if changed != 1:
                    raise SessionError("session already bound")
            except sqlite3.IntegrityError:
                raise SessionError("key already used") from None

    def confirm(self, sid):
        with self.lock, self.db:
            n = self.db.execute("UPDATE sessions SET state='confirmed' WHERE sid=? AND state='uncertain' AND expires>?", (sid, int(time.time()))).rowcount
            if n != 1:
                raise SessionError("session expired")

    def queue_receipt(self, config, message, status):
        """Commit a stable receipt ID before any HTTP request; never queue bytes."""
        if status not in ("confirmed", "retired"):
            raise SessionError("invalid receipt status")
        with self.lock, self.db:
            row = self.db.execute("SELECT kid,state FROM sessions WHERE sid=?", (message["session_id"],)).fetchone()
            if row != (message["key_id"], "confirmed"):
                raise SessionError("unconfirmed receipt")
            if self.db.execute("SELECT count(*) FROM receipts").fetchone()[0] >= self.capacity * 2:
                raise SessionError("receipt capacity reached")
            body = {"receipt_id": str(uuid.uuid4()), "session_id": message["session_id"], "key_id": message["key_id"],
                    "binding": config["pool"], "association": {"master": config["master"], "slave": config["slave"]},
                    "sae_id": config[config["role"]], "status": status}
            self.db.execute("INSERT OR IGNORE INTO receipts(id,sid,status,body) VALUES(?,?,?,?)",
                            (body["receipt_id"], body["session_id"], status, encode(body).decode()))

    def flush_receipts(self, kms):
        with self.lock:
            rows = self.db.execute("SELECT id,body FROM receipts WHERE sent=0 ORDER BY rowid").fetchall()
        for receipt_id, raw in rows:
            kms.protection("receipts", decode(raw.encode()))
            with self.lock, self.db:
                self.db.execute("UPDATE receipts SET sent=1 WHERE id=?", (receipt_id,))

    def close(self):
        self.db.close()


class InnerTLS:
    """OpenSSL TLS 1.3 PSK over the already authenticated TLS stream."""
    def __init__(self, outer, key, identity, server=False):
        if not getattr(ssl, "HAS_PSK", False):
            raise SessionError("Python/OpenSSL PSK support required")
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
        c.minimum_version = c.maximum_version = ssl.TLSVersion.TLSv1_3
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE  # Identity is checked by outer mTLS; inner TLS uses PSK.
        c.options |= ssl.OP_NO_TICKET
        c.set_alpn_protocols([ALPN])
        if server:
            c.num_tickets = 0
            c.set_psk_server_callback(lambda offered: bytes(key) if offered == identity else b"")
        else:
            c.set_psk_client_callback(lambda hint: (identity, bytes(key)))
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.outer = outer
        self.deadline = time.monotonic() + 10
        self.tls = c.wrap_bio(self.incoming, self.outgoing, server_side=server)
        self._call(self.tls.do_handshake)
        # OpenSSL reports an external-PSK handshake as session_reused. Require
        # that result: CERT_NONE must not allow a certificate-authenticated
        # fallback to masquerade as proof of possession of the QKD key.
        if not self.tls.session_reused or self.tls.version() != "TLSv1.3" or self.tls.selected_alpn_protocol() != ALPN:
            raise SessionError("unexpected TLS profile")

    def _flush(self):
        while self.outgoing.pending:
            self.outer.sendall(self.outgoing.read())

    def _call(self, fn, *args):
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise SessionError("TLS confirmation deadline")
            self.outer.settimeout(remaining)
            try:
                result = fn(*args)
                self._flush()
                return result
            except ssl.SSLWantReadError:
                self._flush()
                data = self.outer.recv(MAX_FRAME)
                if not data:
                    raise SessionError("TLS confirmation interrupted")
                self.incoming.write(data)
            except ssl.SSLWantWriteError:
                self._flush()

    def sendall(self, data):
        offset = 0
        while offset < len(data):
            offset += self._call(self.tls.write, data[offset:])

    def recv(self, size):
        return self._call(self.tls.read, size)


def binding(config):
    result = {name: config[name] for name in ("role", "identity", "peer_identity", "master", "slave")}
    result["kms_identity"] = config["kms"]["identity"]
    if "pool" in config:
        pool_context(config)
        result["pool"] = config["pool"]
    return result


def pool_context(config):
    pool = config["pool"]
    fields = {"pool_id", "remote_pool_id", "binding_revision", "service_id", "service_epoch", "purpose"}
    if not isinstance(pool, dict) or set(pool) != fields:
        raise SessionError("invalid pool binding")
    if type(pool["binding_revision"]) is not int or not 0 < pool["binding_revision"] < 2**64:
        raise SessionError("invalid pool revision")
    for field in fields - {"binding_revision"}:
        value = pool[field]
        if not isinstance(value, str) or not 0 < len(value) <= 128 or value.strip() != value or any(c in value for c in "\r\n\x00"):
            raise SessionError("invalid pool reference")
    master, slave = pool["pool_id"], pool["remote_pool_id"]
    if config["role"] == "slave":
        master, slave = slave, master
    return {"service_id": pool["service_id"], "service_epoch": pool["service_epoch"], "purpose": pool["purpose"],
            "master_pool_id": master, "slave_pool_id": slave}


def validate_notification(config, message):
    fields = {"version", "session_id", "key_id", "client", "server", "master", "slave", "expires"}
    if "pool" in config:
        fields.add("pool_context")
    if not isinstance(message, dict) or set(message) != fields:
        raise SessionError("invalid notification")
    if type(message["version"]) is not int or message["version"] != (2 if "pool" in config else 1) or not identifier(message["session_id"]) or not identifier(message["key_id"]):
        raise SessionError("invalid notification")
    if message["client"] != config["peer_identity"] or message["server"] != config["identity"]:
        raise SessionError("notification identity mismatch")
    if message["master"] != config["master"] or message["slave"] != config["slave"]:
        raise SessionError("notification association mismatch")
    if "pool" in config and message["pool_context"] != pool_context(config):
        raise SessionError("notification pool or service mismatch")
    now = int(time.time())
    if type(message["expires"]) is not int or not now < message["expires"] <= now + 60:
        raise SessionError("notification expired")


def protected_application(config, ledger, kms, inner, message, application):
    if "pool" not in config:
        if application is not None:
            application(inner, message)
        return
    ledger.queue_receipt(config, message, "confirmed")
    try:
        ledger.flush_receipts(kms)
        state = kms.protection()
        pool = [p for p in state.get("pools", []) if p.get("pool", {}).get("binding") == config["pool"]]
        if len(pool) != 1 or pool[0].get("allocation_gate") != "":
            raise SessionError("pool held or binding changed; fresh session required")
        if application is not None:
            application(inner, message)
    finally:
        # This means the reference session will no longer call the application.
        # It is not an attestation of a third-party encryptor's secure erasure.
        ledger.queue_receipt(config, message, "retired")
        ledger.flush_receipts(kms)


def receive_session(config, stream, ledger, kms, application=None):
    peer_identity(stream, config["peer_identity"])
    if config["role"] != "slave" or stream.selected_alpn_protocol() != ALPN:
        raise SessionError("wrong application role")
    msg = receive_frame(stream)
    validate_notification(config, msg)
    ledger.begin(msg["session_id"], msg["key_id"], msg["expires"])
    key = kms.retrieve(msg["key_id"])
    try:
        stream.settimeout(max(0.1, min(10, msg["expires"] - time.time())))
        send_frame(stream, {"ready": msg["session_id"]})
        inner = InnerTLS(stream, key, "qkd:" + msg["session_id"] + ":" + msg["key_id"], server=True)
        if receive_frame(inner) != msg:
            raise SessionError("confirmed context mismatch")
        ledger.confirm(msg["session_id"])
        send_frame(inner, msg)
        protected_application(config, ledger, kms, inner, msg, application)
        return {"session_id": msg["session_id"], "key_id": msg["key_id"], "state": "confirmed"}
    finally:
        key[:] = bytes(len(key))


def send_session(config, ledger, kms, application=None):
    if config["role"] != "master":
        raise SessionError("wrong application role")
    sid, expires = str(uuid.uuid4()), int(time.time()) + 30
    ledger.begin(sid, None, expires)
    kid, key = kms.allocate()
    try:
        ledger.bind(sid, kid)
        msg = {"version": 1, "session_id": sid, "key_id": kid, "client": config["identity"],
               "server": config["peer_identity"], "master": config["master"], "slave": config["slave"], "expires": expires}
        if "pool" in config:
            msg["version"] = 2
            msg["pool_context"] = pool_context(config)
        p = config["tls"]
        with socket.create_connection((config["peer_host"], config["peer_port"]), timeout=5) as sock:
            with context(p).wrap_socket(sock, server_hostname=config["peer_host"]) as stream:
                peer_identity(stream, config["peer_identity"])
                if stream.selected_alpn_protocol() != ALPN:
                    raise SessionError("application protocol mismatch")
                stream.settimeout(10)
                send_frame(stream, msg)
                if receive_frame(stream) != {"ready": sid}:
                    raise SessionError("notification rejected")
                inner = InnerTLS(stream, key, "qkd:" + sid + ":" + kid)
                send_frame(inner, msg)
                if receive_frame(inner) != msg:
                    raise SessionError("confirmed context mismatch")
                ledger.confirm(sid)
                protected_application(config, ledger, kms, inner, msg, application)
                return {"session_id": sid, "key_id": kid, "state": "confirmed"}
    finally:
        key[:] = bytes(len(key))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9443)
    args = parser.parse_args()
    config = decode(pathlib.Path(args.config).read_bytes())
    if not getattr(ssl, "HAS_PSK", False):
        raise SessionError("Python 3.13+ with PSK support required")
    ledger = Ledger(config["state_dir"], binding(config))
    kms = KMS(config)
    try:
        if config["role"] == "master":
            print(json.dumps(send_session(config, ledger, kms)), flush=True)
        elif config["role"] == "slave":
            with socket.create_server((args.listen, args.port), backlog=8) as listener:
                print(json.dumps({"event": "listening", "port": listener.getsockname()[1]}), flush=True)
                while True:
                    sock, _ = listener.accept()
                    sock.settimeout(10)
                    try:
                        with context(config["tls"], server=True).wrap_socket(sock, server_side=True) as stream:
                            result = receive_session(config, stream, ledger, kms)
                        print(json.dumps(result), flush=True)
                    except (SessionError, OSError, sqlite3.Error, ValueError, KeyError, TypeError):
                        sock.close()
                        print(json.dumps({"event": "session_failed"}), flush=True)
        else:
            raise SessionError("invalid role")
    finally:
        ledger.close()


if __name__ == "__main__":
    try:
        main()
    except (SessionError, OSError, sqlite3.Error, ValueError, KeyError, TypeError):
        raise SystemExit("application session failed; uncertain keys must not be retried") from None
