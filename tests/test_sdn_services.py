"""Failure and ownership tests around the actual pinned TFS driver contract."""
import copy
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid
from load_tfs_driver import load_driver
Driver = load_driver()
from teraflow.QKDDriver import STATE, CHANGES, ALLOCATION
from teraflow.client import ManagementError, canonical_command
from teraflow.orchestrator import Orchestrator, Incomplete
from teraflow.adapter import SyntheticAdapter


class Domain:
    def __init__(self):
        self.state = {"node_id": str(uuid.uuid4()), "revision": 0,
                      "applications": [{"app_id": str(uuid.uuid4()), "association": {"master": "A", "slave": "B"},
                                        "pool": {"pool_id": "synthetic-pool"}, "rule": {"paused": False, "max_keys_per_request": 4}}]}
        self.commits, self.fail, self.lose, self.sent = {}, False, False, []

    def GetConfig(self, keys):
        return [(STATE, copy.deepcopy(self.state))]

    def SetConfig(self, resources):
        command = copy.deepcopy(resources[0][1]); self.sent.append(command)
        if self.fail:
            return [ManagementError()]
        if command["command_id"] in self.commits:
            return [True] if self.commits[command["command_id"]] == command else [ManagementError(409)]
        if command["expected_revision"] != self.state["revision"]:
            return [ManagementError(409)]
        self.commits[command["command_id"]] = command
        self.state["revision"] += 1
        self.state["applications"][0]["rule"] = command["rule"]
        if self.lose and command["rule"]["paused"] is False:
            self.lose = False
            return [ManagementError()]
        return [True]


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "workflow.json"
        self.domains = {"a": Domain(), "b": Domain()}
        self.desired = {}
        for name, domain in self.domains.items():
            app = domain.state["applications"][0]
            self.desired[name] = dict(node_id=domain.state["node_id"], pool=app["pool"], association=app["association"], rule=app["rule"])

    def runner(self):
        return Orchestrator(self.domains, self.path)

    def test_lost_activation_exact_replay_and_no_intent_replacement(self):
        self.domains["b"].lose = True
        with self.assertRaises(Incomplete): self.runner().run(self.desired)
        job = json.loads(self.path.read_text()); self.assertEqual(job["status"], "partial_activation")
        altered = copy.deepcopy(self.desired); altered["a"]["rule"]["paused"] = True
        with self.assertRaises(ValueError): self.runner().run(altered)
        self.assertEqual(self.runner().run(self.desired)["status"], "complete")
        self.assertEqual([d.state["revision"] for d in self.domains.values()], [3, 3])
        self.assertEqual(self.domains["b"].sent[-1], self.domains["b"].sent[-2])

    def test_provision_barrier_no_activation_when_domain_unreachable(self):
        self.domains["b"].fail = True
        with self.assertRaises(Incomplete): self.runner().run(self.desired)
        self.assertTrue(self.domains["a"].state["applications"][0]["rule"]["paused"])
        self.assertFalse(any(c["rule"]["paused"] is False for d in self.domains.values() for c in d.sent))
        self.domains["b"].fail = False
        self.assertEqual(self.runner().run(self.desired)["status"], "complete")

    def test_revision_conflict_and_abort_preserve_newer_policy(self):
        self.domains["b"].fail = True
        with self.assertRaises(Incomplete): self.runner().run(self.desired)
        a = self.domains["a"]; a.state["revision"] += 1; a.state["applications"][0]["rule"]["max_keys_per_request"] = 1
        self.domains["b"].fail = False
        with self.assertRaises(Incomplete): self.runner().run(self.desired)
        self.assertEqual(a.state["applications"][0]["rule"]["max_keys_per_request"], 1)
        self.assertEqual(self.runner().abort()["status"], "aborted")
        self.assertEqual(a.state["applications"][0]["rule"]["max_keys_per_request"], 1)
        with self.assertRaises(Incomplete): self.runner().run(self.desired)

    def test_partial_abort_retries_and_binding_change_blocks(self):
        self.runner().run(self.desired); self.domains["a"].fail = True
        with self.assertRaises(Incomplete): self.runner().abort()
        job = json.loads(self.path.read_text()); self.assertEqual(job["paused_domains"], ["b"])
        self.domains["a"].fail = False
        self.domains["a"].state["applications"][0]["pool"] = {"pool_id": "different"}
        with self.assertRaises(Incomplete): self.runner().abort()
        self.domains["a"].state["applications"][0]["pool"] = self.desired["a"]["pool"]
        self.assertEqual(self.runner().abort()["status"], "aborted")

    def test_journal_has_single_writer(self):
        with self.runner()._lock():
            with self.assertRaises(BlockingIOError): self.runner().run(self.desired)
        self.assertFalse(self.path.exists())


class MonitorTests(unittest.TestCase):
    def driver(self):
        with patch("teraflow.QKDDriver.Client"):
            driver = Driver("localhost", ca_file="synthetic", cert_file="synthetic", key_file="synthetic", server_identity="urn:test:kms")
        driver.client.state.return_value = {"revision": 5}
        driver.client.changes.return_value = {"revision": 5, "next_revision": 4, "changes": []}
        return driver

    def test_subscription_cursors_errors_unsubscribe_and_termination(self):
        driver = self.driver()
        self.assertEqual(driver.SubscribeState([(STATE, 10, 1), (CHANGES, 10, 1)]), [True, True])
        samples = list(driver.GetState()); self.assertEqual(len(samples), 2); self.assertEqual(driver._cursor, 4)
        self.assertEqual(list(driver.GetState()), [])
        driver.SubscribeState([(CHANGES, 10, 1)]); driver.client.changes.side_effect = ManagementError()
        samples = list(driver.GetState()); self.assertIsInstance(samples[0][2], ManagementError); self.assertEqual(driver._cursor, 4)
        driver.UnsubscribeState([(STATE, 10, 1), (CHANGES, 10, 1)])
        self.assertEqual(list(driver.GetState()), [])
        driver.SubscribeState([(STATE, 10, 1)])
        terminate = threading.Event(); terminate.set()
        self.assertEqual(list(driver.GetState(blocking=True, terminate=terminate)), [])
        driver.Disconnect(); self.assertEqual(list(driver.GetState()), [])

    def test_acknowledgement_timestamp_formatting_preserves_precision(self):
        a = {"service": {"report": {"observed_at": "2026-09-13T12:00:00.123000000+00:00"}}}
        b = {"service": {"report": {"observed_at": "2026-09-13T12:00:00.123Z"}}}
        self.assertEqual(canonical_command(a), canonical_command(b))
        b["service"]["report"]["observed_at"] = "2026-09-13T12:00:00.123000001Z"
        self.assertNotEqual(canonical_command(a), canonical_command(b))

    def test_sampling_bounds_and_adapter_mode_gate(self):
        driver = self.driver()
        for subscription in [(STATE, 10, 0), (STATE, 10, float("nan")), (STATE, 1, 2), ("/unknown", 10, 1)]:
            self.assertIsInstance(driver.SubscribeState([subscription])[0], ValueError)
        for mode in ("pending", "adapter"):
            driver.client.state.return_value = {"links": [{"catalog": {"link_id": "fixture", "mode": mode}}]}
            with self.assertRaises(ValueError): SyntheticAdapter(driver.client).observe("fixture")
        driver.client.apply.assert_not_called()


if __name__ == "__main__":
    unittest.main()
