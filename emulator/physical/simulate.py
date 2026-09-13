"""QNETSIM DES: fiber links, sequential satellite contacts and offline release."""
import argparse
from dataclasses import asdict, replace
import hashlib
import json
import math
from pathlib import Path
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from emulator.physical import bridge
from emulator.physical import geometry as orbital
from emulator.physical.buffers import simulate_buffers
from emulator.physical.model import BB84, C, fiber, pulse_trial, rates
from emulator.physical import fluctuations

HERE = Path(__file__).resolve().parent


def pass_catalog(cfg):
    contacts = cfg.get('passes', [dict(id='pass-1', start_s=0, duration_s=cfg['duration_s'], altitude_km=600)])
    if not 1 <= len(contacts) <= 12: raise ValueError('Expected 1–12 synthetic contact windows')
    previous = 0; seen = set()
    for p in contacts:
        if not isinstance(p['id'],str) or not p['id'] or len(p['id']) > 64 or p['id'] in seen: raise ValueError('Invalid pass ID')
        for key, low, high in [('start_s',previous,cfg['duration_s']),('duration_s',900,1800), ('altitude_km',400,1000),('raan_offset_deg',-10,10)]:
            value = p.get(key, 0 if key == 'raan_offset_deg' else None)
            if not isinstance(value,(int,float)) or not math.isfinite(value) or not low <= value <= high: raise ValueError('Invalid pass '+key)
        previous = p['start_s']+p['duration_s']; seen.add(p['id'])
        if previous > cfg['duration_s']: raise ValueError('Pass outside simulation')
    return contacts


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def validate(cfg):
    if cfg.get('schema') != 'transeuroogs-physical-scenario-v1':
        raise ValueError('Unsupported scenario')
    for name, low, high in [('duration_s', 900, 86400), ('bin_s', .1, 30), ('processing_delay_s', 1, 3600),
                            ('acquisition_s', 0, 60), ('provider_key_limit', 1, 100000)]:
        if not math.isfinite(cfg[name]) or not low <= cfg[name] <= high:
            raise ValueError('Invalid ' + name)
    if type(cfg['provider_key_limit']) is not int or math.ceil(cfg['duration_s']/cfg['bin_s']) > 10000:
        raise ValueError('Invalid key or event limit')
    if len(cfg['terrestrial']) != 2 or len({x['id'] for x in cfg['terrestrial']}) != 2:
        raise ValueError('Expected two distinct terrestrial links')
    if [x['name'] for x in cfg['stations']] != ['Windhof', 'Helmos']:
        raise ValueError('This scenario binds Windhof and Helmos OGSs')
    for site in cfg['stations']:
        for name, low, high in [('latitude', -90, 90), ('longitude', -180, 180), ('altitude_m', 0, 10000), ('diameter_m', .01, 20), ('obscuration_area', 0, .99)]:
            if not math.isfinite(site[name]) or not low <= site[name] <= high: raise ValueError('Invalid station '+name)
    for name, low, high in [('link_capacity_keys', 1, 1024), ('end_to_end_capacity_keys', 1, 1024), ('application_keys_per_request', 1, 128),
                            ('request_interval_s', 1, 3600), ('first_request_s', 0, cfg['duration_s']), ('key_lifetime_s', 1, 86400)]:
        value = cfg['buffers'][name]
        if type(value) is not int or not low <= value <= high: raise ValueError('Invalid buffer '+name)
    sat = cfg['satellite']
    for name, low, high in [('transmit_diameter_m', .01, 2), ('pointing_sigma_urad', 0, 100),
                            ('zenith_transmission', 0, 1), ('receiver_loss_db', 0, 100), ('extra_loss_db', 0, 100)]:
        if not math.isfinite(sat[name]) or not low <= sat[name] <= high:
            raise ValueError('Invalid ' + name)
    BB84(**sat['bb84']).validate()
    pass_catalog(cfg); fluctuations.validate(cfg)
    ids = {'eagle-windhof', 'eagle-helmos'} | {x['id'] for x in cfg['terrestrial']}
    for fault in cfg['faults']:
        if fault['link'] not in ids or fault['kind'] not in ('cloud', 'outage', 'phase_unlock', 'background'):
            raise ValueError('Unknown fault link or kind')
        if not 0 <= fault['start_s'] < fault['end_s'] <= cfg['duration_s']:
            raise ValueError('Invalid fault interval')
    return cfg


def run(cfg, qnetsim_root=bridge.DEFAULT):
    validate(cfg)
    des, qs, manifest = bridge.load(qnetsim_root)
    import numpy as np
    sat = cfg['satellite']
    start = 0.0
    edges = np.arange(0, cfg['duration_s'], cfg['bin_s'])
    widths = np.minimum(cfg['bin_s'], cfg['duration_s']-edges)
    satellite_profile = BB84(**sat['bb84']).validate()
    contacts = pass_catalog(cfg); geometries = {}; contact_at = {}; pass_details = []
    for contact in contacts:
        raw, v, switch_at = orbital.configure(qs, cfg, contact)
        for key in ('C17', 'C19'): v[key] = sat['transmit_diameter_m']
        for key in ('C18', 'C20'): v[key] = sat['pointing_sigma_urad']
        indices = [i for i,edge in enumerate(edges) if contact['start_s'] <= edge+widths[i]/2 < contact['start_s']+contact['duration_s']]
        geometry = orbital.orbit(qs, v, edges[indices]+widths[indices]/2-contact['start_s'])
        optics = [qs.link(site, geometry, satellite_profile.wavelength_nm*1e-9, v,
                         eta_tx=1, eta_rx=10**(-sat['receiver_loss_db']/10), eta_detector=1,
                         zenith_transmission=sat['zenith_transmission']) for site in cfg['stations']]
        geometries[contact['id']] = (geometry,optics,switch_at+contact['start_s'])
        for local, i in enumerate(indices): contact_at[i] = (contact,local)
        pass_details.append(dict(**contact, epoch=v['C33'], switch_at_s=switch_at+contact['start_s'],
                                 orbit_elements={k:v[k] for k in ('C26','C27','C29','C30','C31','C32')}))
    channel_model = fluctuations.Channels(cfg)
    terrestrial_profile = replace(BB84(), symbol_hz=1e8, mus=(.5, .1, .001),
                                  dead_time_ns=10000, parameter_sample_per_basis=10000,
                                  gate_ps=120, wavelength_nm=1550)
    links = {x['id']: dict(kind='fiber', source=x['source'], target=x['target'], vendor_label=x['vendor_label'],
                          profile=terrestrial_profile, settings=x, channel=fiber(x['length_km'], x['attenuation_db_km'], x['insertion_db']))
             for x in cfg['terrestrial']}
    for index, station in enumerate(cfg['stations']):
        links['eagle-'+station['name'].lower()] = dict(kind='space', source='EAGLE-1 model', target=station['name'],
                                                      profile=satellite_profile, index=index, station=station)
    totals = {key: dict(sifted=0., errors=0., proxy_bits=0., last_arrival_s=0., active_seconds=0.) for key in links}
    samples, events = [], []
    env = des.DESEnv('transeuroogs-physical')

    class Network(des.Entity):
        def init(self):
            for i, (edge, width) in enumerate(zip(edges, widths)):
                self.scheduler.schedule_at(round(float(edge)*1e12), des.EventHandler(self, 'emit', [i, float(edge), float(width)]))

        def emit(self, i, edge, width):
            midpoint = edge+width/2
            for key, link in links.items():
                elevation = None
                contact, gi = contact_at.get(i, (None,None))
                pass_id = contact['id'] if contact else None
                dynamics = {}; extra_noise = 0; range_m = None
                if link['kind'] == 'space':
                    name = link['target']; index = link['index']
                    available, loss, delay, switched_at = False, 0., 0., edge
                    if contact:
                        geometry, optics, switch_at = geometries[pass_id]
                        elevation = float(geometry[name+'_elevation_deg'][gi])
                        selected = (index == 0) == (midpoint < switch_at)
                        switched_at = contact['start_s'] if index == 0 else switch_at
                        available = selected and bool(geometry[name+'_visible'][gi])
                        loss = float(optics[index]['optical_eta'][gi])*10**(-sat['extra_loss_db']/10)
                        range_m = float(geometry[name+'_range_m'][gi]); delay = range_m/C
                    dynamics = channel_model.space(link['station'], elevation, pass_id, width)
                    dynamics['mean_optical_eta'] = loss
                    dynamics['transmission_clipped'] = loss*dynamics['irradiance'] > 1
                    loss = min(1., loss*dynamics['irradiance'])
                    extra_noise = dynamics['sky_noise_hz']
                    # Acquisition starts at first geometrically visible sample
                    # in the assigned slot and restarts following an outage.
                else:
                    dynamics = channel_model.fiber(link['settings'],link['profile'],width)
                    available = True; loss = dynamics['optical_eta']; delay = link['channel']['delay_s']
                    extra_noise = dynamics['raman_noise_hz']
                    switched_at = 0
                faulted = [f for f in cfg['faults'] if f['link'] == key and f['start_s'] <= midpoint < f['end_s']]
                available &= not any(f['kind'] in ('cloud', 'outage', 'phase_unlock') for f in faulted)
                if not available:
                    link.pop('acquiring_since', None)
                else:
                    link.setdefault('acquiring_since', max(edge, switched_at))
                active = available and (link['kind'] != 'space' or edge-link['acquiring_since'] >= cfg['acquisition_s'])
                transmission = loss if active else 0
                state = rates(link['profile'], transmission, 10000 if any(f['kind'] == 'background' for f in faulted) else 1, extra_noise)
                if not active:
                    # An unavailable channel never contributes noise-only sifted
                    # data to a future authenticated block.
                    state = {**state, 'qber':None, 'sifted_hz': 0, 'sifted_errors_hz': 0, 'budget_hz': 0, 'detections_hz': 0}
                row = dict(link=key, at_s=edge, duration_s=width, arrival_s=edge+width+delay,
                           active=bool(active), pass_id=pass_id, elevation_deg=elevation, range_m=range_m, delay_s=delay, channel=dynamics,
                           optical_loss_db=-10*math.log10(loss) if loss > 0 else None,
                           **state)
                self.scheduler.schedule_at(round(row['arrival_s']*1e12), des.EventHandler(self, 'receive', [row]))

        def receive(self, row):
            totals[row['link']]['sifted'] += row['sifted_hz']*row['duration_s']
            totals[row['link']]['errors'] += row['sifted_errors_hz']*row['duration_s']
            totals[row['link']]['proxy_bits'] += row['budget_hz']*row['duration_s']
            if row['active']:
                totals[row['link']]['last_arrival_s'] = row['arrival_s']
                totals[row['link']]['active_seconds'] += row['duration_s']
            samples.append(row)

    Network('optical-network', env)
    env.init(); env.run(logging=False, summary=False)
    budgets = {}
    for key, total in totals.items():
        profile = links[key]['profile']
        minimum_block = 2*profile.parameter_sample_per_basis
        sample = math.ceil(total['sifted']*profile.disclosed_fraction)
        observed_qber = total['errors']/total['sifted'] if total['sifted'] else .5
        accepted = total['sifted'] >= minimum_block and observed_qber < profile.max_qber
        # Charge the disclosed sample proportionally and reserve lab auth
        # capacity. This does not implement mission EC, PA or authentication.
        bits = max(0, math.floor(total['proxy_bits']*(1-sample/total['sifted']))-profile.authentication_reserve_bits) if accepted else 0
        ready = total['last_arrival_s']+cfg['processing_delay_s']
        budgets[key] = dict(**total, qber=observed_qber, minimum_block=minimum_block, parameter_sample=sample, accepted=accepted,
                            budget_bits=bits, model_key_count=bits//256, ready_at_sim_s=ready)
        for stage in ('sifting', 'parameter_estimation', 'reconciliation_budget', 'privacy_amplification_budget'):
            events.append(dict(link=key, stage=stage, at_s=ready, accepted=accepted))
    left, right = budgets['eagle-windhof'], budgets['eagle-helmos']
    paired = min(left['model_key_count'], right['model_key_count'], cfg['provider_key_limit'])
    ready = max(left['ready_at_sim_s'], right['ready_at_sim_s'])+cfg['processing_delay_s']
    inputs_sha = hashlib.sha256(canonical(cfg)).hexdigest()
    schedule = dict(schema='transeuroogs-physical-permit-v1', synthetic=True, input_sha256=inputs_sha,
                    link_id='eagle-offline-windhof-helmos',
                    stations=['Windhof', 'Helmos'], key_bits=256, count=paired,
                    left_budget_bits=left['budget_bits'], right_budget_bits=right['budget_bits'],
                    ready_at_sim_s=ready, security_proof_validated=False)
    report = dict(schema='transeuroogs-physical-report-v1', synthetic=True, security_proof_validated=False,
                engine=manifest, input_sha256=inputs_sha, scenario=cfg,
                quasar_input_sha256=raw['sha256'], orbit_start_seconds_after_epoch=start,
                orbit_epoch=pass_details[0]['epoch'], orbit_elements=pass_details[0]['orbit_elements'], switch_at_s=pass_details[0]['switch_at_s'],
                passes=pass_details, stations=cfg['stations'], profiles={k: asdict(x['profile']) for k,x in links.items()},
                budgets=budgets, provider_schedule=schedule, events=events, samples=samples,
                processed_des_events=len(env.future_events),
                needed_SES_input=['operational ephemeris and contact schedule', 'optical source/receiver calibration',
                                  'reference-frame blanking and tracking', 'finite-key/discrete-phase proof and processing agreement',
                                  'offline relay/KID/pool correspondence contract', 'authenticated receiver/vendor interface agreement'])
    buffer_result = simulate_buffers(des, cfg, samples, report['profiles'])
    report.update(buffer_result)
    report['events'].extend(dict(stage='offline_satellite_relay',at_s=x['at_s'],pass_id=x['pass_id'],paired_keys=x['keys'],performed_in='satellite-service-model')
                            for x in buffer_result['buffer_operations'] if x['operation']=='offline_satellite_relay')
    permits = {}
    sources = [('eagle-offline-windhof-helmos', 'satellite-paired', ['Windhof', 'Helmos'], min(left['budget_bits'], right['budget_bits']))]
    sources += [(link['id'], link['id'], [link['source'],link['target']], budgets[link['id']]['budget_bits']) for link in cfg['terrestrial']]
    for link_id, pool, stations, bits in sources:
        grouped = {}; expiries = {}
        for release in buffer_result['buffer_releases'][pool]:
            grouped[release['at_sim_s']] = grouped.get(release['at_sim_s'], 0)+release['count']
            expiries[release['at_sim_s']] = min(expiries.get(release['at_sim_s'],float('inf')),release['expires_at_sim_s'])
        remaining = min(bits//256, cfg['provider_key_limit']); releases = []; used_per_pass = {}
        quota = cfg['provider_key_limit']//len(contacts)
        for at, available in sorted(grouped.items()):
            expiry = expiries[at]
            epoch = next((p['id'] for p in reversed(contacts) if at >= p['start_s']), None)
            available = min(available, max(0, quota-used_per_pass.get(epoch,0)))
            while remaining and available:
                count = min(16, remaining, available)
                # Explicit laboratory gateway disclosure batches; the physical
                # buffer already contains this capacity before each disclosure.
                at = max(at, releases[-1]['at_sim_s']+cfg['bin_s'] if releases else at)
                if at >= expiry: break
                item = dict(at_sim_s=at, count=count)
                if cfg.get('runtime'): item['expires_at_sim_s'] = expiry
                releases.append(item)
                remaining -= count; available -= count
                used_per_pass[epoch] = used_per_pass.get(epoch,0)+count
            if not remaining: break
        permits[link_id] = dict(schedule, link_id=link_id, stations=stations, count=sum(x['count'] for x in releases),
                               left_budget_bits=bits, right_budget_bits=bits, releases=releases,
                               ready_at_sim_s=releases[0]['at_sim_s'] if releases else cfg['duration_s']+cfg['processing_delay_s'])
    report['permits'] = permits
    report['provider_schedule'] = permits['eagle-offline-windhof-helmos']
    return report



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', type=Path, default=HERE / 'scenario.json')
    parser.add_argument('--qnetsim', type=Path, default=bridge.DEFAULT)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = run(json.loads(args.scenario.read_text()), args.qnetsim)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out/'report.json').write_bytes(canonical(report)+b'\n')
    (args.out/'provider-permit.json').write_bytes(canonical(report['provider_schedule'])+b'\n')
    for link_id, permit in report['permits'].items():
        (args.out/(link_id+'-permit.json')).write_bytes(canonical(permit)+b'\n')
    pulse = pulse_trial(BB84(), .02, seed=report['scenario']['seed'])
    (args.out/'pulse-check.json').write_bytes(canonical(pulse)+b'\n')
    print(json.dumps(dict(result='PASS', qnetsim_events=report['processed_des_events'],
                         paired_synthetic_keys=report['provider_schedule']['count'], security_proof_validated=False)))


if __name__ == '__main__':
    main()
