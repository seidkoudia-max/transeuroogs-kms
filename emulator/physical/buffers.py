"""QNETSIM DES key-buffer accounting; tokens represent synthetic capacity.

Every end-to-end establishment burns one key from each of the three paired
link pools. Two endpoint copies share one logical token; they are not counted
twice. Expiry and overflow destroy tokens, and no failed request returns them.
"""
import math


def simulate_buffers(des, cfg, samples, profiles):
    settings = cfg['buffers']; duration = cfg['duration_s']
    pool_names = ['raw-windhof', 'raw-helmos', 'satellite-paired', 'fiber-windhof-jfk', 'fiber-helmos-hellas', 'end-to-end']
    pools = {name: [] for name in pool_names}
    capacities = {name: settings['link_capacity_keys'] for name in pools}
    capacities['end-to-end'] = settings['end_to_end_capacity_keys']
    counters = {name: dict(generated=0, consumed=0, expired=0, overflow=0) for name in pools}
    history, operations, releases = [], [], {name: [] for name in pool_names}
    env = des.DESEnv('transeuroogs-buffers')
    contact_ends = {}
    for row in samples:
        if row['link'].startswith('eagle-') and row['active']:
            contact_ends[row['pass_id']] = max(contact_ends.get(row['pass_id'],0), row['arrival_s'])
    offline_ready = {p:end+2*cfg['processing_delay_s'] for p,end in contact_ends.items()}
    pending = {'satellite-paired': 0, 'end-to-end': 0}
    blocks = {}

    class Buffers(des.Entity):
        def init(self):
            for row in samples:
                self.scheduler.schedule_at(round(row['arrival_s']*1e12), des.EventHandler(self, 'detection_block', [row]))
            ticks = math.ceil(duration/cfg['bin_s'])
            for i in range(ticks+1):
                self.scheduler.schedule_at(round(min(duration, i*cfg['bin_s'])*1e12), des.EventHandler(self, 'tick'))
            t = settings['first_request_s']
            while t <= duration:
                self.scheduler.schedule_at(round(t*1e12), des.EventHandler(self, 'request'))
                t += settings['request_interval_s']

        def now(self): return self.env.now/1e12

        def expire(self):
            for name, queue in pools.items():
                valid = [token for token in queue if token[0] > self.now()]
                counters[name]['expired'] += len(queue)-len(valid)
                pools[name] = valid

        def detection_block(self, row):
            name = row['link']; p = profiles[name]
            pass_id = row['pass_id'] if name.startswith('eagle-') else 'terrestrial'
            if pass_id is None: return
            key = (name,pass_id)
            block = blocks.setdefault(key, dict(sifted=0., errors=0., bits=0., start=self.now()-row['duration_s']))
            block['sifted'] += row['sifted_hz']*row['duration_s']
            block['errors'] += row['sifted_errors_hz']*row['duration_s']
            block['bits'] += row['budget_hz']*row['duration_s']
            if block['sifted'] < 2*p['parameter_sample_per_basis'] or self.now()-block['start'] < 30:
                return
            accepted = block['errors']/block['sifted'] < p['max_qber']
            bits = max(0, math.floor(block['bits']*(1-p['disclosed_fraction']))-p['authentication_reserve_bits']) if accepted else 0
            target = name.replace('eagle-', 'raw-')
            at = self.now()+cfg['processing_delay_s']
            self.scheduler.schedule_at(round(at*1e12), des.EventHandler(self, 'fill', [target, bits//256, at+settings['key_lifetime_s'],pass_id]))
            operations.append(dict(at_s=self.now(), operation='qkd_postprocessing', pool=target, pass_id=pass_id, accepted=accepted, budget_bits=bits))
            blocks[key] = dict(sifted=0., errors=0., bits=0., start=self.now())

        def fill(self, name, count, expiry, pass_id):
            self.expire()
            if name in pending: pending[name] -= count
            counters[name]['generated'] += count
            take = min(count, max(0, capacities[name]-len(pools[name]))) if expiry > self.now() else 0
            if expiry <= self.now(): counters[name]['expired'] += count
            else: counters[name]['overflow'] += count-take
            pools[name].extend([(expiry,pass_id)]*take)
            pools[name].sort()
            if take: releases[name].append(dict(at_sim_s=self.now(), count=take,pass_id=pass_id,expires_at_sim_s=expiry))
            self.transfer()

        def transfer(self):
            self.expire()
            for pass_id, ready in offline_ready.items():
                if self.now() >= ready:
                    self.move(['raw-windhof', 'raw-helmos'], 'satellite-paired', 0, pass_id)
            self.move(['fiber-windhof-jfk', 'satellite-paired', 'fiber-helmos-hellas'], 'end-to-end', .1)

        def move(self, sources, target, delay, pass_id=None):
            eligible = {name:[t for t in pools[name] if pass_id is None or t[1] == pass_id] for name in sources}
            count = min([len(eligible[name]) for name in sources]+[capacities[target]-len(pools[target])-pending[target]])
            if count <= 0: return
            # Reserve/burn atomically at all participating pools in this
            # accounting model. Real multi-KMS transfer is tested separately.
            for _ in range(count):
                taken = {name:eligible[name].pop(0) for name in sources}
                for name, token in taken.items(): pools[name].remove(token)
                expiry = min(token[0] for token in taken.values())
                epoch = pass_id or taken['satellite-paired'][1]
                pending[target] += 1
                self.scheduler.schedule_after(round(delay*1e12), des.EventHandler(self, 'fill', [target, 1, expiry,epoch]))
            for name in sources: counters[name]['consumed'] += count
            operations.append(dict(at_s=self.now(), operation='offline_satellite_relay' if target == 'satellite-paired' else 'protected_end_to_end_establishment', pass_id=pass_id, keys=count))

        def request(self):
            self.expire()
            requested = settings['application_keys_per_request']
            delivered = requested if len(pools['end-to-end']) >= requested else 0
            if delivered:
                del pools['end-to-end'][:delivered]
                counters['end-to-end']['consumed'] += delivered
            operations.append(dict(at_s=self.now(), operation='application_request', master='JFK', slave='HellasQCI', requested=requested, delivered=delivered,
                                   http_status=200 if delivered else 503))
            self.transfer()

        def tick(self):
            self.transfer()
            counts = {name: len(values) for name, values in pools.items()}
            history.append(dict(at_s=self.now(), pools=counts, pending=dict(pending),
                                jfk_key_buffer=counts['end-to-end'], hellasqci_key_buffer=counts['end-to-end']))

    Buffers('key-buffers', env); env.init(); env.run(end_time=round(duration*1e12), logging=False, summary=False)
    delivered = sum(x.get('delivered', 0) for x in operations)
    return dict(buffer_samples=history, buffer_operations=operations, buffer_counters=counters,
                buffer_releases=releases, buffer_final={name: len(value) for name,value in pools.items()},
                matching_end_to_end_model_keys=delivered, buffer_pending_at_end=pending,
                offline_ready_by_pass=offline_ready,
                buffer_model='conditional paired-capacity tokens; actual cryptographic delivery is a separate KMS acceptance test')
