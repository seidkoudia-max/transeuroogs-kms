"""Controller commit verification and state-preserving deployment invariants."""
import importlib.util
import json
from pathlib import Path
import sys
import threading
import tempfile
import time
import unittest
from unittest.mock import Mock, patch, MagicMock
import uuid
from load_tfs_driver import load_driver
Driver = load_driver()
from teraflow.controller import ControllerAdapter
from teraflow.client import ManagementError
from teraflow.QKDDriver import STATE, ALLOCATION

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'deploy/services'))
import service_profile as profile
spec = importlib.util.spec_from_file_location('services_deploy', ROOT / 'deploy/services/deploy.py')
deploy = importlib.util.module_from_spec(spec); spec.loader.exec_module(deploy)


class ControllerTests(unittest.TestCase):
    def test_tfs_endpoints_are_derived_only_from_local_interface_catalog(self):
        with patch('teraflow.QKDDriver.Client'):
            driver = Driver('localhost', ca_file='test', cert_file='test', key_file='test', server_identity='urn:test:kms')
        driver.client.node.return_value = {'qkd_interfaces': {'qkd_interface': [{'qkdi_id': 7}]}}
        self.assertEqual(driver.GetConfig(['__endpoints__']), [('/endpoints/endpoint[qkd-7]', {'uuid': 'qkd-7', 'name': 'QKD interface 7', 'type': 'qkd'})])
        driver.client.node.return_value = {'qkd_interfaces': {'qkd_interface': []}}
        self.assertEqual(driver.GetConfig(['__endpoints__']), [])

    def test_success_requires_exact_durable_kms_commit(self):
        node = str(uuid.uuid4()); observer = Mock(); nbi = Mock()
        command = {'command_id': str(uuid.uuid4()), 'expected_revision': 4, 'association': {'master': 'A', 'slave': 'B'}}
        adapter = ControllerAdapter(node, observer, lambda _: {'node_id': node}, actor='urn:test:controller', nbi=nbi)
        for page in ({'changes': []}, {'changes': [{'actor': 'urn:other', 'revision': 5, 'command': command}]},
                     {'changes': [{'actor': 'urn:test:controller', 'revision': 6, 'command': command}]}):
            observer.changes.return_value = page
            self.assertIsInstance(adapter.SetConfig([(ALLOCATION, command)])[0], ManagementError)
        observer.changes.return_value = {'changes': [{'actor': 'urn:test:controller', 'revision': 5, 'command': command}]}
        self.assertEqual(adapter.SetConfig([(ALLOCATION, command)]), [True])
        self.assertEqual(nbi.request.call_args.args[0:2], ('PUT', '/device/' + node))
        self.assertEqual(adapter.GetConfig([STATE]), [(STATE, {'node_id': node})])
        adapter.snapshot = lambda _: {'node_id': 'other'}
        self.assertIsInstance(adapter.GetConfig([STATE])[0][1], ManagementError)
        nbi.request.side_effect = OSError('lost reply')
        self.assertIsInstance(adapter.SetConfig([(ALLOCATION, command)])[0], ManagementError)

    def test_long_lived_tfs_collector_accepts_late_subscriptions(self):
        with patch('teraflow.QKDDriver.Client'):
            driver = Driver('localhost', ca_file='test', cert_file='test', key_file='test', server_identity='urn:test:kms')
        driver.client.state.return_value = {'revision': 1}
        terminate = threading.Event(); received = threading.Event()
        def collect():
            for _, _, _ in driver.GetState(blocking=True, terminate=terminate):
                received.set(); terminate.set()
        thread = threading.Thread(target=collect); thread.start()
        try:
            time.sleep(0.15)
            self.assertTrue(thread.is_alive())
            driver.SubscribeState([(STATE, 2, 1)])
            self.assertTrue(received.wait(2))
        finally:
            terminate.set(); thread.join(2)
        self.assertFalse(thread.is_alive())


class DeploymentTests(unittest.TestCase):
    def test_only_complete_consistent_workflow_is_adoptable(self):
        spec = importlib.util.spec_from_file_location('services_adopt', ROOT / 'deploy/services/adopt-workflow.py')
        adoption = importlib.util.module_from_spec(spec); spec.loader.exec_module(adoption)
        files = {'link-' + n + '.json': {} for n in profile.NODES}
        files.update({'desired.json': {}, 'workflow.json': {'status': 'complete', 'completed': 1, 'actions': [{}], 'desired': {}}})
        adoption.validate(files)
        files['workflow.json']['status'] = 'partial_activation'
        with self.assertRaises(RuntimeError): adoption.validate(files)
        files['workflow.json']['status'] = 'complete'; files['unexpected.key.pem'] = 'not permitted'
        with self.assertRaises(RuntimeError): adoption.validate(files)

    def test_release_tampering_is_rejected(self):
        import hashlib
        spec = importlib.util.spec_from_file_location('services_build', ROOT / 'deploy/services/build.py')
        builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as d:
            source = Path(d); (source / 'src').mkdir(); (source / 'src/public.py').write_text('original')
            hashes = {'src/public.py': hashlib.sha256(b'original').hexdigest()}
            release = {'files': hashes, 'source_revision': hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()}
            (source / 'release.json').write_text(json.dumps(release))
            self.assertEqual(builder.verify(source), release)
            (source / 'src/stale.py').write_text('unlisted')
            with self.assertRaises(RuntimeError): builder.verify(source)
            (source / 'src/stale.py').unlink()
            (source / 'src/public.py').write_text('altered')
            with self.assertRaises(RuntimeError): builder.verify(source)

    def test_profile_uses_separate_state_and_independent_protected_links(self):
        self.assertEqual(profile.NAMESPACE, 'transeuroogs-services')
        node_ids = {n['node_id'] for n in profile.NODES.values()}; self.assertEqual(len(node_ids), 4)
        pools = []
        for name in profile.NODES:
            c = profile.config(name); pools.append(c['federation']['pools'][0]['binding']['pool_id'])
            self.assertTrue(c['sdn']['principals'][profile.ACTOR]['services'])
            self.assertNotIn('write', c['sdn']['principals'][profile.OBSERVER])
            self.assertTrue(c['sdn']['principals'][profile.ADAPTER]['telemetry'])
            for peer, item in c['inter_kms']['peers'].items():
                if {name, peer} == {'jfk-idq', 'jfk-tq'}:
                    self.assertEqual(item['mode'], 'etsi020')
                else:
                    self.assertEqual(item['mode'], 'qkd-jwe-v1')
                    self.assertEqual(item['link_key_source']['profile'], 'etsi014-link-uuidv4-256-v1')
        self.assertEqual(len(set(pools)), 4)

    def test_restart_never_reseeds_existing_journal_or_mounts_foreign_claim(self):
        for name in list(profile.NODES) + ['link-idq', 'link-tq']:
            objects = deploy.endpoint(name, 'example.invalid/kms@sha256:' + 'a' * 64)
            pod = next(o for o in objects if o['kind'] == 'Deployment')
            spec = pod['spec']['template']['spec']; command = spec['containers'][0]['command'][-1]
            self.assertIn('if [ -e /state/private/state.enc ]; then count=0; fi', command)
            self.assertFalse(spec['automountServiceAccountToken'])
            self.assertEqual(next(v for v in spec['volumes'] if v['name'] == 'state')['persistentVolumeClaim']['claimName'], name + '-state')
            self.assertTrue(all(o['metadata']['namespace'] == profile.NAMESPACE for o in objects))

    def test_foreign_namespace_is_rejected(self):
        with patch.object(deploy, 'kube', return_value=json.dumps({'metadata': {'labels': {'transeuroogs.lab': 'true'}}})):
            with self.assertRaises(RuntimeError): deploy.owned(profile.NAMESPACE, deploy.LABELS)


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        import teraflow.adapter
        import teraflow.orchestrator
        imports = {name: MagicMock() for name in ('grpc', 'common.proto.context_pb2', 'context.client.ContextClient', 'device.client.DeviceClient')}
        for name in ('client', 'controller', 'orchestrator', 'adapter', 'QKDDriver'):
            imports['device.service.drivers.transeuroogs.' + name] = sys.modules['teraflow.' + name]
        spec = importlib.util.spec_from_file_location('services_runtime', ROOT / 'deploy/services/runtime.py')
        self.runtime = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, imports): spec.loader.exec_module(self.runtime)
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.runtime.DATA = Path(self.tmp.name)
        self.keys = {'keys': [{'key_ID': str(uuid.uuid4()), 'key': 'synthetic-test-only'}]}

    def test_lost_master_reply_is_never_retried(self):
        self.runtime.request = Mock(side_effect=OSError('lost reply'))
        with self.assertRaises(OSError): self.runtime.delivery('case')
        with self.assertRaisesRegex(RuntimeError, 'Uncertain'): self.runtime.delivery('case')
        self.assertEqual(self.runtime.request.call_count, 1)

    def test_lost_recipient_reply_is_never_retried(self):
        self.runtime.request = Mock(side_effect=[(200, self.keys), OSError('lost reply')])
        with self.assertRaises(OSError): self.runtime.delivery('case')
        with self.assertRaisesRegex(RuntimeError, 'Uncertain'): self.runtime.delivery('case')
        self.assertEqual(self.runtime.request.call_count, 2)

    def test_prepared_keys_remain_undelivered_until_release_probe(self):
        self.runtime.request = Mock(return_value=(200, self.keys))
        self.runtime.prepare_delivery('incident'); self.runtime.prepare_delivery('incident')
        self.assertEqual(self.runtime.request.call_count, 1)
        receipt = json.loads((self.runtime.DATA / 'delivery-incident.json').read_text())
        self.assertEqual(receipt['status'], 'master_delivered')
        self.assertNotIn('synthetic-test-only', json.dumps(receipt))
        self.runtime.request.side_effect = [(200, self.keys), (503, {})]
        self.runtime.delivery('incident'); self.runtime.delivery('incident')
        self.assertEqual(self.runtime.request.call_count, 3)

    def test_mismatching_recipient_material_is_not_acknowledged(self):
        self.runtime.request = Mock(side_effect=[(200, self.keys), (200, {'keys': []})])
        with self.assertRaisesRegex(RuntimeError, 'mismatch'): self.runtime.delivery('case')
        with self.assertRaisesRegex(RuntimeError, 'Uncertain'): self.runtime.delivery('case')

    def test_recovery_retirement_excludes_delivered_and_unobserved_keys(self):
        source = {str(n): {'ready': n < 55, 'transfer_intent': True, 'master_state': 'AVAILABLE' if n < 55 else 'RESERVED'} for n in range(64)}
        target = {k: v for k, v in source.items() if v['ready']}
        plan = self.runtime.recovery_plan(source, target)
        self.assertEqual(len(plan['healthy_ids']), 55); self.assertEqual(len(plan['retire_ids']), 9)
        source['63']['master_state'] = 'CONSUMED'
        with self.assertRaisesRegex(RuntimeError, 'Refuse retirement'): self.runtime.recovery_plan(source, target)
        source['63']['master_state'] = 'RESERVED'
        del target['1']
        with self.assertRaisesRegex(RuntimeError, 'Ready sets differ'): self.runtime.recovery_plan(source, target)

    def test_service_status_never_claims_expired_or_held_service_is_enabled(self):
        app = {'rule': {'paused': False}, 'service': {'registered': True, 'expires_at': '2999-01-01T00:00:00Z'}}
        self.assertTrue(self.runtime.service_enabled(app))
        app['protection_gate'] = 'incident_hold'
        self.assertFalse(self.runtime.service_enabled(app))
        del app['protection_gate']; app['service']['expires_at'] = '2000-01-01T00:00:00Z'
        self.assertFalse(self.runtime.service_enabled(app))


if __name__ == '__main__': unittest.main()
