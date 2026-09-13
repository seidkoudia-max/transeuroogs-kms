"""Observe four real KMSs through multiple model-driven source refills.

The coordinator waits for non-consuming source inventory before asking JFK's
opt-in stdin laboratory channel to generate application material. It never
retries a consuming key call. Numerical link/buffer observations and actual KMS
counts carry separate timestamps and provenance; no key values enter reports.
"""
import argparse
from functools import lru_cache
import json
from pathlib import Path
import secrets
import selectors
import socket
import subprocess
import sys
import time
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'src/sdn'))
from emulator.physical import profile
from emulator.physical.terrestrial_demo import segments, laboratory_directory
from teraflow.client import Client
from teraflow.physical import PhysicalAdapter, sample, save


def physical_points(report, at):
    return [dict(link=row['link'],at_s=row['at_s'],pass_id=row['pass_id'],active=row['active'],
                 qber=row['qber'],conditional_skr_bps=row['budget_hz'],elevation_deg=row['elevation_deg'],
                 range_m=row['range_m'],channel=row['channel']) for row in report['samples']
            if row['at_s'] <= at < row['at_s']+row['duration_s']]


def choose_provision(report, at, inventories, issued, outstanding):
    if outstanding: return None, 0
    for i,p in enumerate(report['passes']):
        end = report['passes'][i+1]['start_s'] if i+1 < len(report['passes']) else p['start_s']+p['duration_s']+600
        ready = report.get('offline_ready_by_pass',{}).get(p['id'],p['start_s'])
        if ready <= at < end:
            remaining = report['scenario']['runtime']['establish_per_pass']-issued.get(p['id'],0)
            number = min(16,remaining)
            if number > 0 and len(inventories) == 3 and all(x >= number for x in inventories.values()):
                return p['id'],number
    return None,0


class Processes(segments.Processes):
    def start(self, name, args):
        p = subprocess.Popen([str(a) for a in args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.running[name] = p
        return self.event(name,'listening')

    def event(self,name,kind):
        p = self.running[name]
        with selectors.DefaultSelector() as selector:
            selector.register(p.stdout,selectors.EVENT_READ)
            segments.require(bool(selector.select(12)), 'Laboratory response timed out: '+name)
        line = p.stdout.readline()
        segments.require(bool(line), 'Laboratory process stopped: '+name)
        value = json.loads(line)
        segments.require(value.get('event') == kind, 'Unexpected laboratory acknowledgement')
        return value

    def provision(self,count):
        p = self.running['jfk']
        p.stdin.write(json.dumps(dict(count=count))+'\n'); p.stdin.flush()
        response = self.event('jfk','synthetic_provisioned')
        segments.require(response['count'] == count, 'Provisioning acknowledgement mismatch; do not retry')


def run(args):
    require = segments.require
    report = json.loads((args.report_dir/'report.json').read_text()); settings=report['scenario']['runtime']
    speed=args.simulation_speed or settings['simulation_speed']; interval=settings['monitor_interval_sim_s']
    target=settings['establish_per_pass']*len(report['passes'])
    require(1 <= target <= 256 and interval >= 10 and 1 <= speed <= 300, 'Invalid laboratory timeline limits')
    with laboratory_directory(args.state_dir) as directory:
        root=Path(directory); pki=args.prepared_pki or root/'pki'; procs=Processes(); sockets={}
        output=root if args.native_controller else args.report_dir
        if not args.prepared_pki:
            subprocess.run([str(args.pki_binary.resolve()),'--profile','physical','--out',str(pki)],check=True,capture_output=True)
        urls={}; clock=root/'clock.json'; controller=None
        history=[]; telemetry=[]; deliveries=[]; issued={}; seen=set(); sent=set(); delivered=0; last_request=-1e9

        @lru_cache(maxsize=16)
        def context(identity):
            return segments.context(pki,pki,identity)

        def call(name,identity,path,body=None):
            return segments.call(urls[name],context(identity),profile.identity(name),path,body)

        @lru_cache(maxsize=16)
        def manager(name,role):
            u=urllib.parse.urlsplit(urls[name])
            return Client(u.hostname,u.port,ca_file=str(pki/'ca.crt.pem'),cert_file=str(pki/(role+'.crt.pem')),
                          key_file=str(pki/(role+'.key.pem')),server_identity=profile.identity(name))

        def command(name,operation):
            client=manager(name,'controller-sae')
            value=dict(command_id=str(uuid.uuid4()),expected_revision=client.state()['revision'],association=profile.PAIR,service=operation)
            return controller.apply(name,value) if controller else client.apply(value)

        try:
            for link in profile.LINKS:
                name=link['provider']
                event=procs.start(name,[args.source_binary.resolve(),'--pki-dir',pki,'--permit',
                    (args.report_dir/(link['id']+'-permit.json')).resolve(),'--state-dir',root/'spent',
                    '--simulation-speed',speed,'--clock-file',clock])
                urls[name]='https://'+event['address']
            for i,name in enumerate(profile.NAMES):
                sock=socket.socket(); sock.bind(('0.0.0.0' if args.native_controller else '127.0.0.1',8443+i if args.native_controller else 0))
                sockets[name]=sock; urls[name]='https://127.0.0.1:'+str(sock.getsockname()[1])
            for name in reversed(profile.NAMES):
                (root/name).mkdir()
                subprocess.run([str(args.metadata_binary.resolve()),'keygen','--private',str(root/name/'sign.pem'),
                                '--public',str(root/name/'public.pem')],check=True,capture_output=True)
                cfg=profile.config(name,urls,root,pki); config=root/(name+'.json'); config.write_text(json.dumps(cfg))
                address=urls[name].split('://')[1]
                if args.native_controller: address=address.replace('127.0.0.1','0.0.0.0')
                sockets.pop(name).close()
                cmd=[args.binary.resolve(),'--config',config,'--pki-dir',pki,'--certificate-name',name,'--listen',address]
                if name == 'jfk': cmd+=['--synthetic-input-limit',target]
                procs.start(name,cmd)
            if args.native_controller:
                from emulator.physical.native import Controller
                controller=Controller(manager); controller.onboard()
            for name in profile.NAMES:
                for link in manager(name,'observer-sae').state()['links']:
                    command(name,dict(operation='link_create',resource_id=link['catalog']['link_id'],enabled=True))
                command(name,dict(operation='application_create',resource_id=profile.uid('application'),ttl=3600))
            # Observe the zero state before one common clock starts all sources.
            for link in profile.LINKS:
                code,state=call(link['provider'],link['source'],'/api/v1/keys/LINK-SLAVE/status')
                require(code == 200 and state['stored_key_count'] == 0,'Source bypassed common clock barrier')
            start=time.time()+.2; save(clock,round(start*1000)); next_poll=0.
            while True:
                at=max(0.,(time.time()-start)*speed)
                model_at=min(at,report['scenario']['duration_s']-1e-6)
                inventories={}
                for link in profile.LINKS:
                    code,state=call(link['provider'],link['source'],'/api/v1/keys/LINK-SLAVE/status')
                    require(code == 200,'Non-consuming source observation failed')
                    inventories[link['provider']]=state['stored_key_count']
                states={name:manager(name,'observer-sae').state() for name in profile.NAMES}
                counts={name:value['applications'][0]['counts'] for name,value in states.items()}
                physical=physical_points(report,model_at)
                require(len(physical) == 4,'Missing independent physical channel observations')
                history.append(dict(at_sim_s=at,observed_at_unix_s=time.time(),sources=inventories,kms=counts,
                                    physical_links=physical,issued_total=sum(issued.values()),delivered_total=delivered))
                for name in profile.NAMES:
                    client=manager(name,'adapter-sae')
                    for link in profile.LINKS:
                        if name not in (link['source'],link['target']): continue
                        result=PhysicalAdapter(client,root/name/(link['id']+'.outbox')).observe(profile.uid(link['id']),sample(report,link['id'],model_at))
                        if controller: controller.verify(name,profile.uid(link['id']),result['command']['service']['report'])
                        command_id=result['command']['command_id']
                        if (name,command_id) not in sent:
                            sent.add((name,command_id))
                            telemetry.append(dict(at_sim_s=at,node=name,link=link['id'],report=result['command']['service']['report']))
                snapshot=dict(result='RUNNING',matching_application_keys=delivered,endpoints=['JFK','HellasQCI'],synthetic=True,
                              native_controller=bool(controller),
                              input_sha256=report['input_sha256'],latest_physical_links=physical,simulation_time_s=at,
                              physical_telemetry_reports=len(telemetry),pointwise_kms_samples=len(history))
                if controller:
                    save(root/'native-acceptance.json',controller.publish(snapshot)); (root/'ready').touch()
                # Inventory preflight is confined to the exclusive lab coordinator.
                # It does not create a new production reservation protocol.
                outstanding=sum(issued.values())-delivered-counts['jfk']['available']
                pass_id,number=choose_provision(report,at,inventories,issued,outstanding)
                if number:
                    procs.provision(number); issued[pass_id]=issued.get(pass_id,0)+number
                    print(json.dumps(dict(event='application_batch_provisioned',pass_id=pass_id,count=number,at_sim_s=round(at,2))),flush=True)
                batch=settings['application_batch_keys']
                if at-last_request >= settings['application_interval_sim_s'] and counts['jfk']['eligible'] >= batch and delivered+batch <= target-batch:
                    code,first=call('jfk','sae-jfk','/api/v1/keys/SAE-HELLAS/enc_keys',dict(number=batch))
                    require(code == 200 and len(first['keys']) == batch,'Application allocation failed; consuming request will not be retried')
                    ids=[dict(key_ID=x['key_ID']) for x in first['keys']]
                    require(not seen.intersection(x['key_ID'] for x in ids),'Duplicate application ID')
                    code,second=call('hellas','sae-hellas','/api/v1/keys/SAE-JFK/dec_keys',dict(key_IDs=ids))
                    require(code == 200 and len(second['keys']) == batch and all(a['key_ID']==b['key_ID'] and secrets.compare_digest(a['key'],b['key']) for a,b in zip(first['keys'],second['keys'])),'Endpoint key mismatch')
                    seen.update(x['key_ID'] for x in ids); del first,second
                    delivered+=batch; last_request=at
                    deliveries.append(dict(at_sim_s=at,count=batch,matching=True))
                    code,_=call('hellas','sae-hellas','/api/v1/keys/SAE-JFK/dec_keys',dict(key_IDs=ids))
                    require(code == 503,'Consumed keys replayed')
                if at >= report['scenario']['duration_s']:
                    buffered=all(counts[name]['available'] == batch and counts[name]['eligible'] == batch for name in ('jfk','hellas'))
                    if (sum(issued.values()) == target and delivered == target-batch and buffered) or at >= report['scenario']['duration_s']+600: break
                next_poll+=interval
                # No fabricated catch-up samples: retain actual observation time.
                delay=(next_poll-(time.time()-start)*speed)/speed
                if delay > 0: time.sleep(min(delay,1))
                else: next_poll=(time.time()-start)*speed
            save(output/'timeline-observations.json',dict(trace=history,issued_by_pass=issued,deliveries=deliveries,synthetic=True))
            require(all(issued.get(p['id'],0) == settings['establish_per_pass'] for p in report['passes']),'A pass did not supply its requested end-to-end capacity')
            require(delivered == target-settings['application_batch_keys'],'End-to-end delivery target not reached')
            require(all(counts[name]['available'] == batch and counts[name]['eligible'] == batch for name in ('jfk','hellas')),
                    'Endpoint buffers did not both reach the completion target')
            result=dict(snapshot,result='PASS',matching_application_keys=delivered,issued_by_pass=issued,
                        expected_buffer_keys_per_endpoint=target-delivered,delivery_replay_rejected=True,
                        common_source_clock=True,simulation_speed=speed,requested_monitor_interval_sim_s=interval,
                        max_observation_gap_sim_s=max(b['at_sim_s']-a['at_sim_s'] for a,b in zip(history,history[1:])),
                        trace=history,telemetry=telemetry,deliveries=deliveries)
            if not controller:
                # A stopped input-enabled process cannot reopen its persisted
                # session with a fresh provisioning budget.
                procs.crash('jfk')
                cfgpath=root/'jfk.json'
                retry=subprocess.run([str(args.binary.resolve()),'--config',str(cfgpath),'--pki-dir',str(pki),
                                      '--certificate-name','jfk','--synthetic-input-limit',str(target)],
                                     capture_output=True,timeout=10)
                require(retry.returncode != 0,'Restart reset the synthetic input budget')
                result['input_restart_rejected']=True
            save(output/'runtime-acceptance.json',result)
            save(output/'sdn-node.json',{'etsi-qkd-sdn-node:qkd_node':manager('windhof','observer-sae').node()})
            print(json.dumps({k:v for k,v in result.items() if k not in ('trace','telemetry','deliveries','latest_physical_links')}),flush=True)
            if controller:
                from emulator.physical.native import stay
                stay(controller,{k:v for k,v in result.items() if k not in ('trace','telemetry','deliveries')},root/'native-acceptance.json')
        except Exception as error:
            # Preserve public observations on failure without copying key or
            # credential-bearing responses, paths or exception messages.
            try:
                save(output/'runtime-failure.json',dict(result='FAIL',error_type=type(error).__name__,
                     errno=getattr(error,'errno',None),trace=history,issued_by_pass=issued,
                     deliveries=deliveries,synthetic=True,input_sha256=report['input_sha256']))
            except OSError:
                pass
            raise
        finally:
            procs.close()
            for sock in sockets.values(): sock.close()
            if controller: controller.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','source-binary','pki-binary','metadata-binary','report-dir'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--native-controller',action='store_true'); parser.add_argument('--state-dir',type=Path)
    parser.add_argument('--prepared-pki',type=Path)
    parser.add_argument('--simulation-speed',type=float,help='override accelerated clock; recorded in runtime evidence')
    args=parser.parse_args()
    if args.native_controller and (not args.state_dir or not args.prepared_pki): raise ValueError('Native run requires retained state and test PKI')
    try: run(args)
    except Exception as error:
        import traceback
        traceback.print_tb(error.__traceback__)
        detail = str(error) if isinstance(error,RuntimeError) else type(error).__name__
        if isinstance(error,OSError): detail += ' errno='+str(error.errno)
        print('Timeline stopped: '+detail,file=sys.stderr)
        raise SystemExit(1) from None


if __name__=='__main__': main()
