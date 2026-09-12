"""Deployment safety checks; run with Python and PyYAML in the Ubuntu lab."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'deploy/teraflow/deploy-lab.py'
spec = importlib.util.spec_from_file_location('teraflow_lab', MODULE)
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class LabSafetyTests(unittest.TestCase):
    def test_database_password_is_private_and_stable(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(lab, 'STATE', Path(directory)):
            first = lab.persistent_password()
            self.assertEqual(len(first), 48)
            self.assertEqual(first, lab.persistent_password())
            self.assertEqual(stat.S_IMODE(os.stat(Path(directory) / 'database-password').st_mode), 0o600)

    def test_foreign_namespace_is_not_mutated(self):
        existing = json.dumps({'metadata': {'labels': {'owner': 'someone-else'}}})
        with patch.object(lab, 'kube', return_value=existing), patch.object(lab, 'apply') as apply:
            with self.assertRaisesRegex(RuntimeError, 'not owned by this lab'):
                lab.namespace('tfs')
            apply.assert_not_called()

    def test_owned_namespace_can_be_reused(self):
        existing = json.dumps({'metadata': {'labels': lab.OWNER}})
        with patch.object(lab, 'kube', return_value=existing), patch.object(lab, 'apply') as apply:
            lab.namespace('tfs')
            self.assertEqual(apply.call_args.args[0][0]['metadata']['labels'], lab.OWNER)

    def test_partial_stages_reject_absent_or_foreign_namespaces(self):
        for existing in ('', json.dumps({'metadata': {'labels': {'owner': 'someone-else'}}})):
            with self.subTest(existing=existing), patch.object(lab, 'kube', return_value=existing):
                with self.assertRaisesRegex(RuntimeError, 'absent or not lab-owned'):
                    lab.require_owned('tfs')

    def test_image_selects_intel_child_not_arm_or_attestation(self):
        root = 'example.invalid/tfs/device@sha256:' + 'a' * 64
        manifest = {'manifests': [
            {'platform': {'os': 'unknown', 'architecture': 'unknown'}, 'digest': 'sha256:' + 'b' * 64},
            {'platform': {'os': 'linux', 'architecture': 'arm64'}, 'digest': 'sha256:' + 'c' * 64},
            {'platform': {'os': 'linux', 'architecture': 'amd64'}, 'digest': 'sha256:' + 'd' * 64}]}
        outputs = ['', json.dumps([{'RepoDigests': [root]}]), json.dumps(manifest)]
        with patch.object(lab, 'run', side_effect=outputs):
            actual = lab.image_digest('example.invalid/tfs/device:lab', 'amd64')
        self.assertEqual(actual, root.split('@')[0] + '@sha256:' + 'd' * 64)

    def test_image_without_intel_variant_is_rejected(self):
        outputs = ['', json.dumps([{'RepoDigests': ['example.invalid/test@sha256:' + 'a' * 64]}]),
                   json.dumps({'manifests': [{'platform': {'os': 'linux', 'architecture': 'arm64'},
                                              'digest': 'sha256:' + 'b' * 64}]})]
        with patch.object(lab, 'run', side_effect=outputs):
            with self.assertRaises(StopIteration):
                lab.image_digest('example.invalid/test:lab', 'amd64')


if __name__ == '__main__':
    unittest.main()
