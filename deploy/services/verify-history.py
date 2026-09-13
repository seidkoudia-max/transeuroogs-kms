#!/usr/bin/env python3
"""Verify signed KMS history with pinned lab public keys and retain scoped trace."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import uuid
from deploy import STATE, RELEASE, NAMESPACE, LABELS, owned, kube
from service_profile import NODES, PAIR, INVESTIGATOR, identity


def write(path, value):
    with open(path, 'w', opener=lambda p, f: os.open(p, f, 0o600)) as stream:
        stream.write(value); stream.flush(); os.fsync(stream.fileno())


def main():
    if socket.gethostname() != 'lima-transeuroogs-tfs' or not owned(NAMESPACE, LABELS): raise RuntimeError('Owned lab required')
    raw = kube('-n', 'tfs', 'exec', 'deployment/services-test', '--', 'cat', '/state/private/signed-pages.json')
    if len(raw) > 64 << 20: raise RuntimeError('Evidence exceeds bound')
    pages = json.loads(raw)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    directory = STATE / ('evidence-' + digest); directory.mkdir(mode=0o700, exist_ok=True)
    evidence, trust, query, report = [directory / n for n in ('pages.ndjson', 'trust.json', 'query.json', 'report.json')]
    if not report.exists():
        write(evidence, ''.join(json.dumps(p) + '\n' for p in pages))
        now = datetime.now(timezone.utc)
        write(trust, json.dumps([{'issuer': identity(n), 'domain': 'LU-services-lab', 'namespace': 'services-' + n,
            'credential_id': 'synthetic-v1', 'public_key_file': str(STATE / (n + '.pub.pem')), 'pairs': [PAIR],
            'valid_from': (now - timedelta(days=1)).isoformat(), 'valid_until': (now + timedelta(days=1)).isoformat(), 'revoked': False} for n in NODES]))
        subject = next(p['page'] for p in pages if p['page']['issuer'] == identity('jfk-idq'))
        write(query, json.dumps({'incident_id': str(uuid.uuid4()), 'subject': identity('jfk-idq'), 'kind': 'material_exposure',
            'start': subject['history_started_at'], 'end': subject['observed_at'], 'clock_uncertainty_ms': 0, 'limit': 128}))
        subprocess.run([str(RELEASE / 'bin/kms-metadata'), 'trace', '--trust=' + str(trust), '--query=' + str(query),
            '--evidence=' + str(evidence), '--audience=' + INVESTIGATOR, '--out=' + str(report)], check=True)
    result = json.loads(report.read_text())
    if len(result['coverage']) != 4 or not all(c['retained_history_complete'] for c in result['coverage']):
        raise RuntimeError('Incomplete signed history export')
    if not result['findings']: raise RuntimeError('Synthetic custody incident yielded no findings')
    # Pool/namespace correspondence is deliberately not invented by the tracer.
    summary = {'verified_issuers': 4, 'findings': len(result['findings']), 'complete_within_supplied_scope': result['complete_within_supplied_scope'],
               'gaps': result['gaps'], 'evidence_sha256': digest, 'synthetic_incident': True}
    write(STATE / 'history-verification.json', json.dumps(summary, indent=2))
    print(json.dumps(summary))


if __name__ == '__main__': main()
