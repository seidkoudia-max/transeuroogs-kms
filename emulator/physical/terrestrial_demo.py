"""Four local KMS processes on JFK–Windhof–Helmos–HellasQCI, three QKD sources.

The application key is synthetic; each geographic hop consumes distinct source
keys through the existing qkd-jwe-v1 transport. No source material is printed.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from emulator.physical import profile
sys.path.insert(0, str(ROOT/'src/sdn'))
from teraflow.client import Client
from teraflow.physical import PhysicalAdapter, sample
spec = importlib.util.spec_from_file_location('segments', ROOT/'emulator/eagle1-kms/demo.py')
segments = importlib.util.module_from_spec(spec); spec.loader.exec_module(segments)


@contextmanager
def laboratory_directory(state):
    if state:
        state.mkdir(mode=0o700, parents=True, exist_ok=False)
        yield str(state)
    else:
        with tempfile.TemporaryDirectory(prefix='transeuroogs-physical-') as directory:
            yield directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'source-binary', 'pki-binary', 'report-dir'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--metadata-binary', type=Path, required=True)
    parser.add_argument('--native-controller', action='store_true')
    parser.add_argument('--state-dir', type=Path)
    parser.add_argument('--prepared-pki', type=Path)
    args = parser.parse_args()
    require = segments.require
    if args.native_controller and (not args.state_dir or not args.prepared_pki):
        raise ValueError('Native deployment requires persistent session ownership and prepared test credentials')
    with laboratory_directory(args.state_dir) as directory:
        root = Path(directory); pki = root/'pki'; procs = segments.Processes(); sockets = {}
        if args.prepared_pki: pki = args.prepared_pki
        else: subprocess.run([str(args.pki_binary.resolve()), '--profile', 'physical', '--out', str(pki)], check=True, capture_output=True)
        urls, configs, provider_args = {}, {}, {}
        report = json.loads((args.report_dir/'report.json').read_text())
        trace, began = [], time.monotonic()
        controller = None

        def observe(name, count, stage):
            trace.append(dict(elapsed_s=round(time.monotonic()-began, 4), node=name, key_count=count, stage=stage))

        def manager(name, role):
            uri = urllib.parse.urlsplit(urls[name])
            return Client(uri.hostname, uri.port, ca_file=str(pki/'ca.crt.pem'), cert_file=str(pki/(role+'.crt.pem')),
                          key_file=str(pki/(role+'.key.pem')), server_identity=profile.identity(name))

        def apply_command(name, operation):
            c = manager(name, 'controller-sae')
            item = dict(command_id=str(uuid.uuid4()), expected_revision=c.state()['revision'], association=profile.PAIR, service=operation)
            if controller: return controller.apply(name, item)
            return c.apply(item)

        def call(name, identity, path, body=None):
            return segments.call(urls[name], segments.context(pki, pki, identity), profile.identity(name), path, body)

        try:
            for name, model in [(x['provider'],x['id']) for x in profile.LINKS]:
                permit = args.report_dir/(model+'-permit.json')
                metadata = json.loads(permit.read_text())
                require(metadata['count'] >= 32, 'Insufficient modelled link budget for this acceptance run')
                command = [args.source_binary.resolve(), '--pki-dir', pki, '--permit', permit.resolve(),
                           '--state-dir', root/'spent', '--simulation-speed', 80]
                provider_args[name] = command
                urls[name] = 'https://'+procs.start(name, command)['address']
                identity = next(x['source'] for x in profile.LINKS if x['provider'] == name)
                code, status = call(name, identity, '/api/v1/keys/LINK-SLAVE/status')
                require(code == 200 and status['stored_key_count'] == 0, 'Fiber exposed inventory before processing completed')
                observe(name, status['stored_key_count'], 'before-release')
                code, _ = call(name, 'sae-jfk', '/api/v1/keys/LINK-SLAVE/status')
                require(code == 401, 'Application impersonated a link-source gateway')
            deadline = time.monotonic()+20
            for name, identity in [(x['provider'],x['source']) for x in profile.LINKS]:
                while True:
                    code, data = call(name, identity, '/api/v1/keys/LINK-SLAVE/status')
                    observe(name, data.get('stored_key_count', 0), 'source-buffer-fill')
                    if code == 200 and data['stored_key_count'] >= 32: break
                    require(time.monotonic() < deadline, 'Fiber postprocessing did not release inventory')
                    time.sleep(.05)
            for index, name in enumerate(profile.NAMES):
                sock = socket.socket(); sock.bind(('0.0.0.0' if args.native_controller else '127.0.0.1', 8443+index if args.native_controller else 0)); sockets[name] = sock
                urls[name] = 'https://127.0.0.1:'+str(sock.getsockname()[1])
            for name in profile.NAMES:
                (root/name).mkdir()
                subprocess.run([str(args.metadata_binary.resolve()), 'keygen', '--private', str(root/name/'sign.pem'),
                                '--public', str(root/name/'public.pem')], check=True, capture_output=True)
                cfg = profile.config(name, urls, root, pki)
                path = root/(name+'.json'); path.write_text(json.dumps(cfg))
                configs[name] = [args.binary.resolve(), '--config', path, '--pki-dir', pki, '--certificate-name', name,
                                 '--listen', urls[name].split('://')[1].replace('127.0.0.1','0.0.0.0') if args.native_controller else urls[name].split('://')[1]]
            for name in reversed(list(profile.NAMES)):
                sockets.pop(name).close()
                procs.start(name, configs[name]+['--synthetic-keys', 32 if name == 'jfk' else 0])
            if args.native_controller:
                from emulator.physical.native import Controller
                controller = Controller(manager); controller.onboard()
            for name in profile.NAMES:
                for link in manager(name, 'observer-sae').state()['links']:
                    apply_command(name, dict(operation='link_create', resource_id=link['catalog']['link_id'], enabled=True))
                # Existing end-to-end keys remain usable between optical passes;
                # do not couple delivery authorization to instantaneous SKR.
                apply_command(name, dict(operation='application_create', resource_id=profile.uid('application'), ttl=3600))
            telemetry = []
            for at in (100, 900):
                for name in profile.NAMES:
                    client = manager(name, 'adapter-sae')
                    for link in profile.LINKS:
                        if name not in (link['source'], link['target']): continue
                        result = PhysicalAdapter(client, root/name/(link['id']+'.outbox.json')).observe(profile.uid(link['id']), sample(report, link['id'], at))
                        if controller:
                            controller.verify(name, profile.uid(link['id']), result['command']['service']['report'])
                        telemetry.append(dict(node=name, at_s=at, link=link['id'], report=result['command']['service']['report']))
            captured = manager('windhof', 'observer-sae').node()
            output_dir = root if args.native_controller else args.report_dir
            (output_dir/'sdn-node.json').write_text(json.dumps({'etsi-qkd-sdn-node:qkd_node':captured}))
            deadline = time.monotonic()+45
            while True:
                code, data = call('jfk', 'sae-jfk', '/api/v1/keys/SAE-HELLAS/status')
                observe('jfk', data.get('stored_key_count', 0), 'end-to-end-fill')
                if code == 200 and data['stored_key_count'] == 32: break
                require(time.monotonic() < deadline, 'Protected physical-source relay did not complete')
                time.sleep(.1)
            code, first = call('jfk', 'sae-jfk', '/api/v1/keys/SAE-HELLAS/enc_keys', {'number': 8})
            require(code == 200 and len(first['keys']) == 8, 'Source application delivery failed')
            ids = [{'key_ID': x['key_ID']} for x in first['keys']]
            code, second = call('hellas', 'sae-hellas', '/api/v1/keys/SAE-JFK/dec_keys', {'key_IDs': ids})
            require(code == 200 and len(second['keys']) == 8, 'Destination application delivery failed')
            require(all(a['key_ID'] == b['key_ID'] and secrets.compare_digest(a['key'], b['key']) for a,b in zip(first['keys'], second['keys'])), 'Key mismatch')
            del first, second
            code, status = call('jfk', 'sae-jfk', '/api/v1/keys/SAE-HELLAS/status')
            require(code == 200 and status['stored_key_count'] == 24, 'Endpoint buffer did not debit eight delivered keys')
            observe('jfk', 24, 'after-first-delivery')
            if controller:
                from emulator.physical.native import stay
                result = dict(result='PASS', matching_application_keys=8, endpoints=['JFK','HellasQCI'],
                              native_controller=True, physical_telemetry_reports=len(telemetry), synthetic=True,
                              expected_buffer_keys_per_endpoint=24, input_sha256=report['input_sha256'])
                print(json.dumps(result), flush=True)
                stay(controller, result, root/'native-acceptance.json')
            action = dict(action_id=str(uuid.uuid4()), incident_id=str(uuid.uuid4()), pool_id=profile.pool('jfk'),
                          expected_revision=0, operation='hold', reason='synthetic physical-lab incident')
            code, _ = call('jfk', 'sae-jfk', '/federation/v1/actions', action)
            require(code == 403, 'Application gained incident authority')
            for _ in range(2):
                code, held = call('jfk', 'protection-sae', '/federation/v1/actions', action)
                require(code == 200 and held['revision'] == 1, 'Pool hold or exact replay failed')
            for name in ('jfk', 'hellas'):
                procs.crash(name); procs.start(name, configs[name])
            code, _ = call('hellas', 'sae-hellas', '/api/v1/keys/SAE-JFK/dec_keys', {'key_IDs': ids})
            require(code == 503, 'Destination restart revived spent keys')
            code, _ = call('jfk', 'sae-jfk', '/api/v1/keys/SAE-HELLAS/enc_keys', {'number':1})
            require(code == 503, 'Restart lost the incident hold')
            action.update(action_id=str(uuid.uuid4()), expected_revision=1, operation='release')
            code, _ = call('jfk', 'protection-sae', '/federation/v1/actions', action)
            require(code == 200, 'Authorized hold release failed')
            consumption = {}
            for name, identity, model in [(x['provider'],x['source'],x['id']) for x in profile.LINKS]:
                code, status = call(name, identity, '/api/v1/keys/LINK-SLAVE/status')
                count = json.loads((args.report_dir/(model+'-permit.json')).read_text())['count']
                require(code == 200 and 0 <= status['stored_key_count'] < count, 'Geographic relay bypassed its link source')
                consumption[name] = count-status['stored_key_count']
                procs.crash(name)
                replay = subprocess.run([str(x) for x in provider_args[name]], capture_output=True, timeout=8)
                require(replay.returncode != 0, 'Restart regenerated a spent physical link permit')
            code, first = call('jfk', 'sae-jfk', '/api/v1/keys/SAE-HELLAS/enc_keys', {'number':24})
            require(code == 200 and len(first['keys']) == 24, 'Established keys became unusable after QKD sources stopped')
            later_ids = [{'key_ID':x['key_ID']} for x in first['keys']]
            require(not {x['key_ID'] for x in later_ids}.intersection(x['key_ID'] for x in ids), 'Reused delivered key ID')
            code, second = call('hellas', 'sae-hellas', '/api/v1/keys/SAE-JFK/dec_keys', {'key_IDs':later_ids})
            require(code == 200 and len(second['keys']) == 24 and all(a['key_ID'] == b['key_ID'] and secrets.compare_digest(a['key'], b['key']) for a,b in zip(first['keys'], second['keys'])), 'Buffered endpoint copies differ')
            del first, second
            code, status = call('jfk', 'sae-jfk', '/api/v1/keys/SAE-HELLAS/status')
            require(code == 200 and status['stored_key_count'] == 0, 'End-to-end buffer did not deplete')
            observe('jfk', 0, 'after-buffer-depletion')
            result = dict(result='PASS', matching_application_keys=32, physical_budgeted_link_consumption=consumption,
                          trusted_relays=['Windhof OGS', 'Helmos OGS'], endpoints=['JFK', 'HellasQCI'], transport='qkd-jwe-v1', synthetic=True,
                          restart_replay_rejected=True, physical_telemetry_reports=len(telemetry),
                          durable_incident_hold=True, buffered_delivery_with_qkd_sources_stopped=True)
            (args.report_dir/'runtime-acceptance.json').write_text(json.dumps(dict(result, trace=trace, telemetry=telemetry), indent=2)+'\n')
            print(json.dumps(result))
        finally:
            procs.close()
            for sock in sockets.values(): sock.close()


if __name__ == '__main__':
    try: main()
    except Exception as exc:
        import traceback
        traceback.print_tb(exc.__traceback__)
        print('Physical fiber acceptance failed: '+(str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__), file=sys.stderr)
        raise SystemExit(1) from None
