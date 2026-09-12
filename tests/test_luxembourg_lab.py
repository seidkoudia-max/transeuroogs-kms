"""Guard the two-vendor, three-site synthetic topology and role boundaries."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

DIRECTORY = Path(__file__).resolve().parents[1] / 'deploy/luxembourg'
sys.path.insert(0, str(DIRECTORY))
import lux_profile as profile
spec = importlib.util.spec_from_file_location('lux_deploy', DIRECTORY / 'deploy.py')
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)
import acceptance


class LuxembourgProfileTests(unittest.TestCase):
    def test_standard_interworking_stays_at_shared_trusted_site(self):
        standard = [link for link in profile.TOPOLOGY['links'] if link['mode'] == 'etsi020']
        self.assertEqual([(link['from'], link['to']) for link in standard], [('jfk-idq', 'jfk-tq')])
        for link in standard:
            self.assertEqual(profile.NODES[link['from']]['site'], profile.NODES[link['to']]['site'])
            self.assertNotEqual(profile.NODES[link['from']]['domain'], profile.NODES[link['to']]['domain'])
        self.assertEqual([link['mode'] for link in profile.TOPOLOGY['links']], ['lab-relay', 'etsi020', 'lab-relay'])

    def test_only_edge_sites_deliver_application_keys(self):
        expected = {'windhof': ['SAE-WINDHOF'], 'jfk-idq': [], 'jfk-tq': [], 'betzdorf': ['SAE-BETZDORF']}
        for name, local in expected.items():
            cfg = profile.config(name)
            self.assertEqual(cfg['inter_kms']['local_saes'], local)
            self.assertEqual(cfg['inter_kms']['target_kmes']['SAE-BETZDORF'], 'betzdorf')
            self.assertNotIn(profile.CONTROLLER, cfg['identities'])
            self.assertNotIn(profile.INVESTIGATOR, cfg['identities'])
            self.assertEqual(uuid.UUID(cfg['sdn']['node_id']).version, 4)

    def test_relay_does_not_invent_provider_evidence(self):
        for name in ('jfk-idq', 'jfk-tq', 'betzdorf'):
            rule = profile.config(name)['sdn']['applications'][0]['rule']
            self.assertEqual(rule['allowed_sources'], ['unknown'])
            self.assertFalse(rule['require_evidence'])
            self.assertEqual(rule['max_generation_age_seconds'], 0)

    def test_initial_deployments_are_stopped_and_have_independent_volumes(self):
        claims = set()
        for name in profile.NODES:
            resources = deploy.endpoint(name, 'example.invalid/kms@sha256:' + 'a' * 64)
            workload = next(obj for obj in resources if obj['kind'] == 'Deployment')
            self.assertEqual(workload['spec']['replicas'], 0)
            self.assertEqual(workload['spec']['strategy']['type'], 'Recreate')
            volumes = workload['spec']['template']['spec']['volumes']
            claim = next(v['persistentVolumeClaim']['claimName'] for v in volumes if v['name'] == 'state')
            self.assertNotIn(claim, claims)
            claims.add(claim)
            policy = next(obj for obj in resources if obj['kind'] == 'NetworkPolicy')
            adjacent = policy['spec']['ingress'][0]['from'][1]['podSelector']['matchExpressions'][0]['values']
            self.assertEqual(set(adjacent), set(profile.config(name)['inter_kms']['peers']))

    def test_interrupted_delivery_requires_inspection_and_cannot_be_skipped(self):
        plan = [('start', lambda: None, False), ('deliver', lambda: None, True)]
        with self.assertRaisesRegex(RuntimeError, 'Interrupted delivery'):
            acceptance.remaining({'completed': ['start'], 'active': 'deliver'}, plan)
        with self.assertRaisesRegex(RuntimeError, 'plan changed'):
            acceptance.remaining({'completed': ['deliver'], 'active': None}, plan)
        with self.assertRaisesRegex(RuntimeError, 'Invalid active'):
            acceptance.remaining({'completed': ['start'], 'active': 'start'}, plan)
        self.assertEqual(acceptance.remaining({'completed': ['start', 'deliver'], 'active': None}, plan), [])
        self.assertEqual(acceptance.remaining({'completed': [], 'active': 'start'}, plan), plan)

    def test_all_actual_deliveries_require_uncertain_checkpoint_recovery(self):
        protected = {name for name, _, needs_review in acceptance.steps() if needs_review}
        self.assertEqual(len(protected), 6)
        self.assertTrue(all('master' in name or 'slave' in name for name in protected))

    def test_concurrent_acceptance_cannot_consume_the_same_test_batch(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(acceptance, 'DATA', Path(directory)):
            with acceptance.acquire_lock():
                with self.assertRaisesRegex(RuntimeError, 'Another acceptance'):
                    acceptance.acquire_lock()
            with acceptance.acquire_lock():
                self.assertEqual((Path(directory) / 'acceptance.lock').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
