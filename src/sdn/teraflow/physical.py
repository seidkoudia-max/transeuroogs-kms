"""Metadata-only playback of conditional QNETSIM rates into SYNTHETIC links.

The adapter cannot provision physical equipment or carry key material. A durable
outbox retains exact command/revision ownership across uncertain replies.
"""
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import uuid


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name+'.tmp')
    with open(temporary, 'w', opener=lambda p, f: os.open(p, f, 0o600)) as stream:
        json.dump(value, stream, allow_nan=False); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def sample(report, model_link, at_s):
    if report.get('schema') != 'transeuroogs-physical-report-v1' or report.get('synthetic') is not True or report.get('security_proof_validated') is not False:
        raise ValueError('Only explicit synthetic physical reports are accepted')
    digest = report.get('input_sha256', '')
    if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
        raise ValueError('Invalid scenario digest')
    if not math.isfinite(at_s) or at_s < 0:
        raise ValueError('Invalid simulation time')
    buffers = [x for x in report.get('buffer_samples', []) if x['at_s'] <= at_s < x['at_s']+report['scenario']['bin_s']]
    pool = 'satellite-paired' if model_link == 'eagle-offline-windhof-helmos' else model_link
    keys = buffers[0]['pools'].get(pool, 0) if len(buffers) == 1 else 0
    if model_link == 'eagle-offline-windhof-helmos':
        if len(buffers) != 1 or at_s > report['scenario']['duration_s']:
            raise ValueError('Satellite service observation outside the simulation')
        return dict(scenario=digest, model_link=model_link, at_s=buffers[0]['at_s'], active=False,
                    qber=0., budget_hz=0., buffer_keys=keys)
    rows = [row for row in report['samples'] if row['link'] == model_link and row['at_s'] <= at_s < row['at_s']+row['duration_s']]
    if len(rows) != 1:
        raise ValueError('No unique simulation interval; stale/overlapping data rejected')
    row = rows[0]
    if type(row['active']) is not bool:
        raise ValueError('Invalid active state')
    for key in ('qber', 'budget_hz', 'sifted_hz'):
        if not math.isfinite(row[key]) or row[key] < 0 or row[key] > (1 if key == 'qber' else 2**32-1):
            raise ValueError('Invalid physical rate')
    # Whitelist the metadata, never copy arbitrary report fields into SDN.
    return dict(scenario=digest, model_link=model_link, at_s=row['at_s'], active=row['active'],
                qber=row['qber'], budget_hz=row['budget_hz'], buffer_keys=keys)


class PhysicalAdapter:
    def __init__(self, client, journal):
        self.client = client
        self.journal = Path(journal)

    def observe(self, link_id, observation):
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        with open(self.journal.with_name(self.journal.name+'.lock'), 'a',
                  opener=lambda p, f: os.open(p, f, 0o600)) as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            return self._observe(link_id, observation)

    def _observe(self, link_id, observation):
        fingerprint = hashlib.sha256(json.dumps(observation, sort_keys=True, allow_nan=False).encode()).hexdigest()
        previous = json.loads(self.journal.read_text()) if self.journal.exists() else None
        if previous:
            if previous['link_id'] != link_id:
                raise ValueError('Outbox is bound to another link')
            if previous['fingerprint'] == fingerprint:
                if previous['status'] == 'committed':
                    return previous['result']
                return self._send(previous)
            if previous['status'] != 'committed':
                raise RuntimeError('Uncertain telemetry must resolve its original command first')
            old = previous['observation']
            if old['scenario'] != observation['scenario'] or old['model_link'] != observation['model_link'] or old['at_s'] >= observation['at_s']:
                raise ValueError('Outbox cannot rewind or switch scenarios')
        state = self.client.state()
        matches = [x for x in state['links'] if x['catalog']['link_id'] == link_id]
        if len(matches) != 1 or matches[0]['catalog']['mode'] != 'synthetic':
            raise ValueError('Physical playback requires a synthetic catalog entry')
        link = matches[0]; desired = link['state']
        enabled = desired['present'] and desired['enabled']
        active = enabled and observation['active'] and observation['budget_hz'] > 0
        status = 'ACTIVE' if active else ('PASSIVE' if enabled and observation.get('buffer_keys', 0) > 0 else 'OFF')
        report = dict(sequence=desired.get('report', {}).get('sequence', 0)+1,
                      desired_revision=desired['desired_revision'], observed_at=datetime.now(timezone.utc).isoformat(),
                      status=status, interface_status='ENABLED' if enabled else 'DISABLED',
                      skr=math.floor(observation['budget_hz']) if active else 0,
                      eskr=math.floor(observation['budget_hz']*.9) if active else 0,
                      qber=f"{100*observation['qber']:.3f}")
        if observation['model_link'] == 'eagle-offline-windhof-helmos':
            # A paired-key service has no single optical QBER. Never fabricate
            # a zero-error photon measurement for the completed middle segment.
            report.pop('qber')
        item = dict(link_id=link_id, fingerprint=fingerprint, observation=observation, status='pending',
                    command=dict(command_id=str(uuid.uuid4()), expected_revision=state['revision'],
                                 association=link['catalog']['association'],
                                 service=dict(operation='link_report', resource_id=link_id, report=report)))
        save(self.journal, item)
        return self._send(item)

    def _send(self, item):
        result = self.client.apply(item['command'])
        # Client validates the KMS response. Never rebase a failed CAS or replace
        # an uncertain command; a concurrent desired-state change needs review.
        item.update(status='committed', result=result)
        save(self.journal, item)
        return result
