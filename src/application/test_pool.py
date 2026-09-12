"""Pool binding is checked before the consuming slave KMS request."""
import copy
import time
import tempfile
import session
import unittest
import uuid

from session import SessionError, binding, pool_context, validate_notification


class PoolBindingTests(unittest.TestCase):
    def setUp(self):
        self.master = {"role": "master", "identity": "urn:app:a", "peer_identity": "urn:app:b", "master": "A", "slave": "B",
                       "kms": {"identity": "urn:kms:a"}, "pool": {"pool_id": "LU/OGS/GR/final", "remote_pool_id": "GR/OGS/LU/final",
                       "binding_revision": 2, "service_id": "LU-GR-final", "service_epoch": "lab-1", "purpose": "application-tls"}}
        self.slave = copy.deepcopy(self.master)
        self.slave.update(role="slave", identity="urn:app:b", peer_identity="urn:app:a")
        self.slave["pool"].update(pool_id="GR/OGS/LU/final", remote_pool_id="LU/OGS/GR/final", binding_revision=5)
        self.msg = {"version": 2, "session_id": str(uuid.uuid4()), "key_id": str(uuid.uuid4()), "client": "urn:app:a", "server": "urn:app:b",
                    "master": "A", "slave": "B", "expires": int(time.time()) + 30, "pool_context": pool_context(self.master)}

    def test_corresponding_local_names_and_revisions(self):
        self.assertEqual(pool_context(self.master), pool_context(self.slave))
        validate_notification(self.slave, self.msg)
        changed = copy.deepcopy(self.master)
        changed["pool"]["binding_revision"] += 1
        self.assertNotEqual(binding(self.master), binding(changed))

    def test_wrong_service_epoch_purpose_pool_and_downgrade(self):
        for field in self.msg["pool_context"]:
            changed = copy.deepcopy(self.msg)
            changed["pool_context"][field] = "wrong"
            with self.assertRaises(SessionError):
                validate_notification(self.slave, changed)
        changed = copy.deepcopy(self.msg)
        changed.pop("pool_context")
        changed["version"] = 1
        with self.assertRaises(SessionError):
            validate_notification(self.slave, changed)
        self.slave["pool"]["binding_revision"] = True
        with self.assertRaises(SessionError):
            pool_context(self.slave)


class ReceiptOutboxTests(unittest.TestCase):
    def test_lost_reply_reuses_receipt_id_across_restart(self):
        fixture = PoolBindingTests()
        fixture.setUp()
        config, message = fixture.master, fixture.msg
        class KMS:
            def __init__(self):
                self.calls = []
                self.fail = True
            def protection(self, path, body):
                self.calls.append(body)
                if self.fail:
                    raise SessionError("lost receipt reply")
        kms = KMS()
        with tempfile.TemporaryDirectory() as directory:
            ledger = session.Ledger(directory, binding(config))
            ledger.begin(message["session_id"], message["key_id"], message["expires"])
            ledger.confirm(message["session_id"])
            ledger.queue_receipt(config, message, "confirmed")
            with self.assertRaises(SessionError):
                ledger.flush_receipts(kms)
            ledger.close()
            ledger = session.Ledger(directory, binding(config))
            kms.fail = False
            ledger.flush_receipts(kms)
            ledger.queue_receipt(config, message, "retired")
            ledger.flush_receipts(kms)
            ledger.flush_receipts(kms)
            ledger.close()
        self.assertEqual(kms.calls[0], kms.calls[1])
        self.assertEqual([x["status"] for x in kms.calls], ["confirmed", "confirmed", "retired"])
        self.assertNotIn("Material", str(kms.calls))
