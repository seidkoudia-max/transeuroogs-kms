"""Physical laws, protocol limits, independent fault and SDN replay checks."""
import copy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
import math
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT/'src/sdn'))
from emulator.physical.model import BB84, fiber, rates, pulse_trial
from emulator.physical.simulate import validate, run
from emulator.physical import bridge
from emulator.physical import profile
from teraflow.physical import PhysicalAdapter, sample
from deploy.physical.install import objects, verify


class PhysicsTests(unittest.TestCase):
    def test_fiber_power_and_propagation(self):
        a, b = fiber(10, .2, 0), fiber(20, .2, 0)
        self.assertAlmostEqual(b['optical_eta'], a['optical_eta']**2)
        self.assertAlmostEqual(b['delay_s'], 2*a['delay_s'])
        self.assertAlmostEqual(a['delay_s'], 48.96721e-6, places=10)
        with self.assertRaises(ValueError): fiber(-1)

    def test_zero_loss_noise_visibility_and_deadtime(self):
        p = BB84()
        self.assertEqual(rates(p, 0)['budget_hz'], 0)
        low, high = rates(p, 1e-4), rates(p, 1e-2)
        self.assertGreater(high['budget_hz'], low['budget_hz'])
        self.assertGreater(low['detector_live_fraction'], high['detector_live_fraction'])
        self.assertEqual(rates(replace(p, visibility=0), .1)['budget_hz'], 0)
        self.assertEqual(rates(replace(p, optical_error=.5), .1)['budget_hz'], 0)
        self.assertGreater(rates(p, .001, 10000)['qber'], rates(p, .001)['qber'])
        self.assertLess(rates(replace(p, gate_ps=40), .01)['gate_acceptance'], rates(p, .01)['gate_acceptance'])
        for value in (float('nan'), float('inf'), -1, 2):
            with self.assertRaises(ValueError): rates(p, value)

    def test_nonvacuum_decoys_and_no_security_claim(self):
        p = BB84(); result = rates(p, .01)
        self.assertEqual([x['mu'] for x in result['intensities']], [.63, .14, .001])
        self.assertGreater(result['intensities'][2]['detections_hz'], 0)
        self.assertGreater(result['intensities'][0]['sifted_hz'], result['intensities'][1]['sifted_hz'])

    def test_phase_encoded_receiver_and_resource_limit(self):
        p = replace(BB84(), visibility=1, optical_error=0, phase_sigma_rad=0, noise_hz_per_detector=0,
                    dead_time_ns=0, jitter_fwhm_ps=0)
        clean = pulse_trial(p, .5, symbols=20000)
        self.assertGreater(clean['counts']['sifted'], 100)
        self.assertEqual(clean['counts']['errors'], 0)
        self.assertEqual(clean['exported_keys'], 0)
        noisy = pulse_trial(replace(p, visibility=0), .5, symbols=20000)
        self.assertGreater(noisy['qber'], .4)
        self.assertLess(noisy['qber'], .6)
        with self.assertRaises(ValueError): pulse_trial(p, .5, symbols=200001)

    def test_missing_engine_never_falls_back(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError): bridge.load(d)


class AdapterTests(unittest.TestCase):
    def report(self):
        return dict(schema='transeuroogs-physical-report-v1', synthetic=True, security_proof_validated=False,
                    input_sha256='a'*64, samples=[dict(link='fiber', at_s=0, duration_s=2, active=True,
                                                     qber=.025, budget_hz=1200, sifted_hz=4000, secret='never-forward')])

    def client(self, mode='synthetic'):
        client = Mock()
        client.state.return_value = dict(revision=1, links=[dict(catalog=dict(link_id='link', mode=mode, association={'master':'A','slave':'B'}),
                                                                 state=dict(present=True, enabled=True, desired_revision=1))])
        client.apply.side_effect = lambda command: dict(command=command, revision=2)
        return client

    def test_units_whitelist_and_uncertain_replay(self):
        observation = sample(self.report(), 'fiber', 1)
        self.assertNotIn('secret', observation)
        with tempfile.TemporaryDirectory() as d:
            c = self.client(); a = PhysicalAdapter(c, Path(d)/'outbox.json')
            c.apply.side_effect = OSError('lost response')
            with self.assertRaises(OSError): a.observe('link', observation)
            first = copy.deepcopy(c.apply.call_args.args[0])
            with self.assertRaises(RuntimeError): a.observe('link', dict(observation, at_s=2))
            c.apply.side_effect = lambda command: dict(command=command, revision=2)
            result = PhysicalAdapter(c, Path(d)/'outbox.json').observe('link', observation)
            self.assertEqual(result['command'], first)
            self.assertEqual(first['service']['report']['qber'], '2.500')
            self.assertEqual(first['service']['report']['skr'], 1200)
            a.observe('link', observation)
            self.assertEqual(c.apply.call_count, 2)
            with self.assertRaises(ValueError): a.observe('link', dict(observation, at_s=-1))

    def test_refuses_hardware_stale_and_forged_claims(self):
        report = self.report()
        with self.assertRaises(ValueError): sample(report, 'fiber', 2)
        report['security_proof_validated'] = True
        with self.assertRaises(ValueError): sample(report, 'fiber', 0)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                PhysicalAdapter(self.client('adapter'), Path(d)/'outbox').observe('link', sample(self.report(), 'fiber', 0))

    def test_concurrent_writers_send_once(self):
        with tempfile.TemporaryDirectory() as d:
            client = self.client()
            observation = sample(self.report(), 'fiber', 0)
            def submit(_):
                return PhysicalAdapter(client, Path(d)/'outbox').observe('link', observation)
            with ThreadPoolExecutor(max_workers=8) as workers:
                results = list(workers.map(submit, range(16)))
            self.assertEqual(client.apply.call_count, 1)
            self.assertTrue(all(result == results[0] for result in results))

    def test_satellite_stored_pool_has_no_optical_qber(self):
        report = self.report()
        report.update(scenario=dict(bin_s=2, duration_s=1200),
                      buffer_samples=[dict(at_s=900, pools={'satellite-paired':24})])
        observation = sample(report, 'eagle-offline-windhof-helmos', 901)
        with tempfile.TemporaryDirectory() as d:
            result = PhysicalAdapter(self.client(), Path(d)/'outbox').observe('link', observation)
        telemetry = result['command']['service']['report']
        self.assertEqual(telemetry['status'], 'PASSIVE')
        self.assertEqual(telemetry['skr'], 0)
        self.assertNotIn('qber', telemetry)
        with self.assertRaises(ValueError): sample(report, 'eagle-offline-windhof-helmos', 902)


class DeploymentTests(unittest.TestCase):
    def test_pool_bindings_are_reciprocal_across_qci_domains(self):
        urls = {name: 'https://localhost:8443' for name in (*profile.NAMES, 'link-lux', 'eagle-pair', 'link-hellas')}
        configs = {name: profile.config(name, urls, Path('/state'), Path('/test-pki')) for name in profile.NAMES}
        pools = {name: cfg['federation']['pools'][0] for name, cfg in configs.items()}
        for left, right in [('jfk','hellas'), ('windhof','helmos')]:
            a, b = pools[left], pools[right]
            self.assertEqual(a['binding']['remote_pool_id'], b['binding']['pool_id'])
            self.assertEqual(b['binding']['remote_pool_id'], a['binding']['pool_id'])
            self.assertNotEqual(a['domain_id'], a['remote_domain_id'])
            self.assertEqual(a['remote_domain_id'], b['domain_id'])
            self.assertEqual(a['remote_ogs_id'], b['ogs_id'])
            self.assertEqual(b['remote_ogs_id'], a['ogs_id'])

    def test_release_tampering_or_extra_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d); payload = source/'public.txt'; payload.write_bytes(b'public')
            files = {'public.txt': hashlib.sha256(b'public').hexdigest()}
            release = dict(files=files, source_revision=hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest())
            (source/'release.json').write_text(json.dumps(release))
            self.assertEqual(verify(source), release)
            payload.write_bytes(b'tampered')
            with self.assertRaises(RuntimeError): verify(source)
            payload.write_bytes(b'public')
            extra = source/'unlisted'; extra.write_bytes(b'extra')
            with self.assertRaises(RuntimeError): verify(source)

    def test_pod_retains_state_and_exposes_only_kms_ports(self):
        service, policy, pod = objects('lab@sha256:'+'a'*64, 'run-test', dict(source_revision='b'*64))
        self.assertEqual([p['port'] for p in service['spec']['ports']], [8443,8444,8445,8446])
        self.assertTrue(service['spec']['publishNotReadyAddresses'])
        spec = pod['spec']; container = spec['containers'][0]
        self.assertEqual(spec['restartPolicy'], 'Never')
        self.assertFalse(spec['automountServiceAccountToken'])
        self.assertTrue(container['securityContext']['readOnlyRootFilesystem'])
        self.assertFalse(container['securityContext']['allowPrivilegeEscalation'])
        self.assertEqual(spec['volumes'][0]['persistentVolumeClaim']['claimName'], 'physical-state')
        self.assertIn('/state/run-test', container['command'])
        ingress = policy['spec']['ingress'][0]
        self.assertEqual([p['port'] for p in ingress['ports']], [8443,8444,8445,8446])
        self.assertEqual(ingress['from'][0]['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name'], 'tfs')


class QNETSIMAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Full DES is a separate explicit target; generic CI still executes all
        # model and security-boundary tests without the user's private runtime.
        import os
        if os.environ.get('QNETSIM_ACCEPTANCE') != '1':
            raise unittest.SkipTest('Run make physical-test for pinned QNETSIM DES acceptance')
        cls.cfg = json.loads((ROOT/'emulator/physical/scenario.json').read_text())
        cls.baseline = run(cls.cfg)

    def test_exclusive_contacts_delay_budget_and_determinism(self):
        report = self.baseline
        space = [x for x in report['samples'] if x['link'].startswith('eagle-') and x['active']]
        self.assertEqual(len(space), len({x['at_s'] for x in space}))
        self.assertTrue(all(x['arrival_s'] > x['at_s']+x['duration_s'] for x in space))
        self.assertEqual(report['provider_schedule']['count'], 64)
        self.assertGreater(report['provider_schedule']['ready_at_sim_s'], max(x['arrival_s'] for x in space))
        self.assertEqual(report, run(self.cfg))
        self.assertFalse(report['security_proof_validated'])
        self.assertEqual([x['name'] for x in report['stations']], ['Windhof','Helmos'])
        self.assertEqual([x['length_km'] for x in report['scenario']['terrestrial']], [25,30])
        self.assertGreater(report['budgets']['fiber-windhof-jfk']['budget_bits'], report['budgets']['fiber-helmos-hellas']['budget_bits'])

    def test_buffers_conserve_capacity_and_pairing(self):
        report = self.baseline
        for name, counters in report['buffer_counters'].items():
            self.assertEqual(counters['generated'], counters['consumed']+counters['expired']+counters['overflow']+report['buffer_final'][name])
        for row in report['buffer_samples']:
            self.assertEqual(row['jfk_key_buffer'], row['hellasqci_key_buffer'])
            for name, count in row['pools'].items():
                cap = self.cfg['buffers']['end_to_end_capacity_keys' if name == 'end-to-end' else 'link_capacity_keys']
                self.assertLessEqual(count, cap); self.assertGreaterEqual(count, 0)
        end = report['buffer_counters']['end-to-end']
        self.assertGreater(end['consumed'], 0)
        for name in ('fiber-windhof-jfk','satellite-paired','fiber-helmos-hellas'):
            self.assertGreaterEqual(report['buffer_counters'][name]['consumed'], end['generated'])
        for permit in report['permits'].values():
            self.assertEqual(sum(x['count'] for x in permit['releases']), permit['count'])
            self.assertLessEqual(permit['count']*256, permit['left_budget_bits'])
            self.assertLessEqual(permit['count']*256, permit['right_budget_bits'])

    def test_expiry_before_offline_completion_cannot_be_recycled(self):
        cfg = copy.deepcopy(self.cfg); cfg['buffers']['key_lifetime_s'] = 10
        result = run(cfg)
        self.assertEqual(result['matching_end_to_end_model_keys'], 0)
        self.assertEqual(result['provider_schedule']['count'], 0)
        self.assertTrue(any(x['expired'] > 0 for x in result['buffer_counters'].values()))

    def test_cloud_stops_pairing_and_fiber_outage_has_local_scope(self):
        cfg = copy.deepcopy(self.cfg)
        cfg['faults'] = [dict(link='eagle-helmos', kind='cloud', start_s=0, end_s=1200),
                         dict(link='fiber-windhof-jfk', kind='outage', start_s=0, end_s=1200)]
        result = run(cfg)
        self.assertEqual(result['provider_schedule']['count'], 0)
        self.assertEqual(result['budgets']['fiber-windhof-jfk']['budget_bits'], 0)
        self.assertGreater(result['budgets']['fiber-helmos-hellas']['budget_bits'], 0)
        self.assertGreater(result['budgets']['eagle-windhof']['budget_bits'], 0)
        self.assertEqual(result['matching_end_to_end_model_keys'], 0)

    def test_phase_unlock_and_insufficient_block(self):
        cfg = copy.deepcopy(self.cfg)
        cfg['satellite']['bb84']['parameter_sample_per_basis'] = 10**12
        self.assertEqual(run(cfg)['provider_schedule']['count'], 0)
        cfg = copy.deepcopy(self.cfg)
        cfg['faults'] = [dict(link='eagle-windhof', kind='phase_unlock', start_s=0, end_s=1200)]
        self.assertEqual(run(cfg)['provider_schedule']['count'], 0)


if __name__ == '__main__': unittest.main()
