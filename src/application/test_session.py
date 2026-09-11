import concurrent.futures
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

import session


class Sessions(unittest.TestCase):
    def test_durable_duplicate_and_concurrent_notification(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = session.Ledger(directory, {"pair": "A-B"})
            sid, kid = str(uuid.uuid4()), str(uuid.uuid4())
            def attempt(_):
                try:
                    ledger.begin(sid, kid, int(time.time()) + 30)
                    return 1
                except session.SessionError:
                    return 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                self.assertEqual(sum(executor.map(attempt, range(16))), 1)
            ledger.close()
            ledger = session.Ledger(directory, {"pair": "A-B"})
            with self.assertRaises(session.SessionError):
                ledger.begin(str(uuid.uuid4()), kid, int(time.time()) + 30)
            ledger.close()
            with self.assertRaises(session.SessionError):
                session.Ledger(directory, {"pair": "A-C"})

    def test_unknown_allocation_and_expiry_are_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = session.Ledger(directory, {}, capacity=2)
            sid = str(uuid.uuid4())
            ledger.begin(sid, None, int(time.time()) - 1)
            with self.assertRaises(session.SessionError):
                ledger.confirm(sid)
            with self.assertRaises(session.SessionError):
                ledger.begin(sid, None, int(time.time()) + 30)
            ledger.close()

    def test_notification_binding_and_malformed_json(self):
        c = {"peer_identity": "A", "identity": "B", "master": "ma", "slave": "sl"}
        m = {"version": 1, "session_id": str(uuid.uuid4()), "key_id": str(uuid.uuid4()),
             "client": "A", "server": "B", "master": "ma", "slave": "sl", "expires": int(time.time()) + 30}
        session.validate_notification(c, m)
        for field, wrong in [("client", "C"), ("server", "A"), ("master", "xx"), ("key_id", "not-uuid"),
                             ("expires", int(time.time()) - 1), ("version", True)]:
            with self.assertRaises(session.SessionError):
                session.validate_notification(c, dict(m, **{field: wrong}))
        with self.assertRaises(session.SessionError):
            session.decode(b'{"key_id":"one","key_id":"two"}')

    def _handshake(self, matching=True, identity=True):
        self.assertTrue(getattr(ssl, "HAS_PSK", False), "Python 3.13+ with PSK required")
        left, right = socket.socketpair()
        key = bytearray(b"a" * 32)
        failure = []
        def server():
            try:
                tls = session.InnerTLS(right, key, "test-identity", server=True)
                self.assertEqual(session.receive_frame(tls), {"client": "A", "server": "B"})
                session.send_frame(tls, {"confirmed": True})
            except (ssl.SSLError, session.SessionError, OSError):
                failure.append(True)
            finally:
                right.close()
        thread = threading.Thread(target=server)
        thread.start()
        try:
            tls = session.InnerTLS(left, key if matching else bytearray(b"b" * 32), "test-identity" if identity else "wrong")
            session.send_frame(tls, {"client": "A", "server": "B"})
            result = session.receive_frame(tls)
        except (ssl.SSLError, session.SessionError, OSError):
            result = None
        finally:
            left.close()
            thread.join(timeout=12)
        self.assertFalse(thread.is_alive())
        if matching and identity:
            self.assertEqual(result, {"confirmed": True})
            self.assertFalse(failure)
        else:
            self.assertIsNone(result)
            self.assertTrue(failure)

    def test_standard_tls_psk_confirmation(self):
        self._handshake()

    def test_matching_id_with_wrong_bytes_fails(self):
        self._handshake(matching=False)

    def test_wrong_psk_identity_fails(self):
        self._handshake(identity=False)

    def test_certificate_fallback_is_not_key_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            key, cert = pathlib.Path(directory) / "key.pem", pathlib.Path(directory) / "cert.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                            "-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=synthetic-fallback", "-days", "1"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            c.minimum_version = c.maximum_version = ssl.TLSVersion.TLSv1_3
            c.load_cert_chain(cert, key)
            c.set_alpn_protocols([session.ALPN])
            left, right = socket.socketpair()
            def fallback():
                try:
                    with c.wrap_socket(right, server_side=True) as stream:
                        stream.recv(1)
                except OSError:
                    pass
            thread = threading.Thread(target=fallback)
            thread.start()
            try:
                with self.assertRaises(session.SessionError):
                    session.InnerTLS(left, bytearray(b"a" * 32), "unused-psk")
            finally:
                left.close()
                thread.join(timeout=10)
            self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
