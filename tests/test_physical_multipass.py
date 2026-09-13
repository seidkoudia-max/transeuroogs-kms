"""Independent stochastic channels, pass isolation and runtime preflight."""
import copy
import json
import os
from pathlib import Path
import statistics
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from emulator.physical.fluctuations import Channels, gamma_parameters, gamma_draw, raman_noise, stream
from emulator.physical.model import BB84
from emulator.physical.simulate import run, validate
from emulator.physical.timeline import choose_provision, physical_points


class ChannelTests(unittest.TestCase):
    def test_gamma_gamma_moments_and_zero_turbulence(self):
        alpha,beta=gamma_parameters(.8)
        rng=stream(2026,'moments')
        data=[gamma_draw(rng,alpha,beta) for _ in range(40000)]
        self.assertAlmostEqual(statistics.mean(data),1,delta=.025)
        expected=1/alpha+1/beta+1/(alpha*beta)
        self.assertAlmostEqual(statistics.variance(data),expected,delta=.08*expected)
        self.assertEqual(gamma_draw(rng,*gamma_parameters(0)),1)
        a,b=gamma_parameters(.8,.1)
        self.assertLess(1/a+1/b+1/(a*b),expected)
        with self.assertRaises(ValueError): gamma_parameters(float('nan'))

    def test_raman_power_bandwidth_direction_and_zero_limits(self):
        args=[25,.2,1e-5,1e-9,.1,1550,.6]
        forward=raman_noise(*args)
        self.assertGreater(raman_noise(*args,direction='backward'),forward)
        for index in (2,4):
            doubled=args.copy(); doubled[index]*=2
            self.assertAlmostEqual(raman_noise(*doubled),2*forward)
        for index in (0,2,3):
            zero=args.copy(); zero[index]=0
            self.assertEqual(raman_noise(*zero),0)
        args[1]=0
        self.assertEqual(raman_noise(*args),raman_noise(*args,direction='backward'))

    def test_preflight_never_generates_during_starvation_or_pending_transfer(self):
        report=dict(passes=[dict(id='p1',start_s=0,duration_s=1200)],scenario=dict(runtime=dict(establish_per_pass=32)))
        self.assertEqual(choose_provision(report,900,dict(a=16,b=0,c=16),{},False),(None,0))
        self.assertEqual(choose_provision(report,900,dict(a=16,b=16,c=16),{},True),(None,0))
        self.assertEqual(choose_provision(report,900,dict(a=16,b=16,c=16),{},False),('p1',16))
        self.assertEqual(choose_provision(report,1300,dict(a=16,b=16,c=16),{},False),('p1',16))
        self.assertEqual(choose_provision(report,2000,dict(a=16,b=16,c=16),{},False),(None,0))
        self.assertEqual(choose_provision(report,900,dict(a=16,b=16,c=16),{'p1':32},False),(None,0))

    def test_insertion_fluctuation_cannot_create_optical_gain(self):
        channel=Channels(dict(seed=4))
        link=dict(id='fiber',length_km=25,attenuation_db_km=.2,insertion_db=3,
                  fluctuations=dict(loss_sigma_db=10,correlation_s=0))
        for _ in range(100):
            point=channel.fiber(link,BB84(),2)
            self.assertLessEqual(point['optical_eta'],10**(-5/10))

    def test_rejects_overlapping_passes_and_invalid_noise(self):
        cfg=json.loads((ROOT/'emulator/physical/multipass.json').read_text())
        cfg['passes'][1]['start_s']=100
        with self.assertRaises(ValueError): validate(cfg)
        cfg=json.loads((ROOT/'emulator/physical/multipass.json').read_text())
        cfg['terrestrial'][0]['fluctuations']['classical_power_w']=-1
        with self.assertRaises(ValueError): validate(cfg)


class MultipassAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get('QNETSIM_ACCEPTANCE') != '1': raise unittest.SkipTest('Requires pinned QNETSIM runtime')
        cls.cfg=json.loads((ROOT/'emulator/physical/multipass.json').read_text())
        cls.report=run(cls.cfg)

    def test_four_independent_time_series_and_reproducibility(self):
        report=self.report
        self.assertEqual(report,run(self.cfg))
        self.assertEqual(len(physical_points(report,900)),4)
        for link in report['budgets']:
            rows=[x for x in report['samples'] if x['link']==link]
            active=[x for x in rows if x['active']]
            self.assertGreater(max(x['qber'] for x in active)-min(x['qber'] for x in active),1e-5)
            self.assertGreater(max(x['budget_hz'] for x in active)-min(x['budget_hz'] for x in active),1)
            self.assertTrue(all(x['qber'] is None and x['budget_hz']==0 for x in rows if not x['active']))
        for p in report['passes']:
            contacts=[x for x in report['samples'] if x['pass_id']==p['id'] and x['active'] and x['link'].startswith('eagle-')]
            self.assertEqual(len(contacts),len({x['at_s'] for x in contacts}))
        self.assertLess(report['provider_schedule']['releases'][0]['at_sim_s'],report['passes'][1]['start_s'])

    def test_each_pass_refills_without_recycling_expired_capacity(self):
        r=self.report
        for permit in r['permits'].values():
            self.assertEqual(permit['count'],192)
            for p in r['passes']:
                releases=[x for x in permit['releases'] if p['start_s'] <= x['at_sim_s'] < p['start_s']+p['duration_s']]
                self.assertEqual(sum(x['count'] for x in releases),64)
                self.assertTrue(all(x['expires_at_sim_s'] > x['at_sim_s'] for x in releases))
        for name,c in r['buffer_counters'].items():
            self.assertEqual(c['generated'],c['consumed']+c['expired']+c['overflow']+r['buffer_final'][name])
        self.assertGreater(r['buffer_counters']['end-to-end']['expired'],0)
        self.assertGreater(r['buffer_counters']['fiber-windhof-jfk']['expired'],0)

    def test_changing_one_fiber_does_not_change_other_channels(self):
        cfg=copy.deepcopy(self.cfg)
        cfg['terrestrial'][0]['fluctuations']['classical_power_w']*=10
        changed=run(cfg)
        for a,b in zip(self.report['samples'],changed['samples']):
            if a['link'] != 'fiber-windhof-jfk': self.assertEqual(a,b)
        baseline=[x['qber'] for x in self.report['samples'] if x['link']=='fiber-windhof-jfk']
        noisy=[x['qber'] for x in changed['samples'] if x['link']=='fiber-windhof-jfk']
        self.assertGreater(statistics.mean(noisy),statistics.mean(baseline))

    def test_unmatched_contacts_from_different_passes_never_pair(self):
        cfg=copy.deepcopy(self.cfg); cfg['passes']=cfg['passes'][:2]; cfg['duration_s']=7200
        cfg['buffers']['key_lifetime_s']=86400
        cfg['faults']=[dict(link='eagle-helmos',kind='cloud',start_s=0,end_s=1200),
                       dict(link='eagle-windhof',kind='cloud',start_s=6000,end_s=7200)]
        r=run(cfg)
        self.assertGreater(r['budgets']['eagle-windhof']['budget_bits'],0)
        self.assertGreater(r['budgets']['eagle-helmos']['budget_bits'],0)
        self.assertEqual(r['provider_schedule']['count'],0)
        self.assertEqual(r['matching_end_to_end_model_keys'],0)


if __name__=='__main__': unittest.main()
