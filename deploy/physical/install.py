"""Install the owned local emulation pod alongside TeraFlow, retaining all runs.

Run on the dedicated Lima VM against a verified public bundle. Reinstallation
requires --new-run; it creates a new synthetic session without deleting prior
encrypted journals or spent-permit markers. No application key values are read.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import uuid

NS = 'transeuroogs-physical'
LABELS = {'transeuroogs.lab':'true','transeuroogs.profile':'physical-v1'}
ROOT = Path('/opt/transeuroogs')
PKI_NAMES = ['ca.crt.pem']+[name+suffix for name in ('jfk','windhof','helmos','hellas','link-lux','eagle-pair','link-hellas',
             'sae-jfk','sae-hellas','controller-sae','observer-sae','adapter-sae','protection-sae','unknown-sae') for suffix in ('.crt.pem','.key.pem')]


def run(args, data=None):
    return subprocess.check_output(args,input=data,text=True)


def kube(*args,data=None): return run(['sudo','microk8s','kubectl',*args],data)


def apply(items):
    return kube('apply','-f','-',data=json.dumps({'apiVersion':'v1','kind':'List','items':items}))


def verify(source):
    release = json.loads((source/'release.json').read_text())
    actual = {str(p.relative_to(source)) for p in source.rglob('*') if p.is_file() and p != source/'release.json'}
    if actual != set(release['files']): raise RuntimeError('Public release inventory mismatch')
    for name,digest in release['files'].items():
        if (source/name).resolve().is_relative_to(source.resolve()) is False or hashlib.sha256((source/name).read_bytes()).hexdigest()!=digest:
            raise RuntimeError('Public release hash mismatch')
    if hashlib.sha256(json.dumps(release['files'],sort_keys=True).encode()).hexdigest()!=release['source_revision']:
        raise RuntimeError('Release fingerprint mismatch')
    return release


def secret(name,namespace,files):
    return {'apiVersion':'v1','kind':'Secret','metadata':{'name':name,'namespace':namespace,'labels':LABELS},'type':'Opaque',
            'data':{key:base64.b64encode(value).decode() for key,value in files.items()}}


def objects(image, session, release):
    label=dict(LABELS,app='physical-lab')
    command=['python','/opt/transeuroogs-physical/emulator/physical/terrestrial_demo.py','--binary','/opt/transeuroogs-physical/bin/kms',
             '--source-binary','/opt/transeuroogs-physical/bin/physical-source','--pki-binary','/opt/transeuroogs-physical/bin/test-pki',
             '--metadata-binary','/opt/transeuroogs-physical/bin/kms-metadata','--report-dir','/opt/transeuroogs-physical/data',
             '--native-controller','--state-dir','/state/'+session,'--prepared-pki','/run/physical-pki']
    pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':'physical-lab','namespace':NS,'labels':label,'annotations':{'transeuroogs.release':release['source_revision']}},
         'spec':{'restartPolicy':'Never','automountServiceAccountToken':False,
                 'securityContext':{'runAsUser':65532,'runAsGroup':65532,'fsGroup':65532},
                 'containers':[{'name':'lab','image':image,'command':command,
                     'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
                     'resources':{'requests':{'cpu':'100m','memory':'256Mi'},'limits':{'cpu':'2','memory':'1Gi'}},
                     'env':[{'name':k,'value':v} for k,v in {'PYTHONUNBUFFERED':'1','PYTHONDONTWRITEBYTECODE':'1',
                         'CONTEXTSERVICE_SERVICE_HOST':'contextservice.tfs.svc.cluster.local','CONTEXTSERVICE_SERVICE_PORT_GRPC':'1010',
                         'DEVICESERVICE_SERVICE_HOST':'deviceservice.tfs.svc.cluster.local','DEVICESERVICE_SERVICE_PORT_GRPC':'2020'}.items()],
                     'readinessProbe':{'exec':{'command':['test','-f','/state/'+session+'/ready']},'periodSeconds':5},
                     'volumeMounts':[{'name':'state','mountPath':'/state'},{'name':'pki','mountPath':'/run/physical-pki','readOnly':True},{'name':'tmp','mountPath':'/tmp'}]}],
                 'volumes':[{'name':'state','persistentVolumeClaim':{'claimName':'physical-state'}},
                            {'name':'pki','secret':{'secretName':'physical-pki','defaultMode':0o440}}, {'name':'tmp','emptyDir':{'medium':'Memory','sizeLimit':'64Mi'}}]}}
    service={'apiVersion':'v1','kind':'Service','metadata':{'name':'physical-lab','namespace':NS,'labels':LABELS},
             'spec':{'publishNotReadyAddresses':True,'selector':{'app':'physical-lab'},
                     'ports':[{'name':name,'port':8443+i,'targetPort':8443+i} for i,name in enumerate(('jfk','windhof','helmos','hellas'))]}}
    policy={'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{'name':'physical-lab-boundary','namespace':NS,'labels':LABELS},
            'spec':{'podSelector':{'matchLabels':{'app':'physical-lab'}},'policyTypes':['Ingress','Egress'],
                    'ingress':[{'from':[{'namespaceSelector':{'matchLabels':{'kubernetes.io/metadata.name':'tfs'}}}],
                                'ports':[{'protocol':'TCP','port':8443+i} for i in range(4)]}],
                    'egress':[{'to':[{'namespaceSelector':{'matchLabels':{'kubernetes.io/metadata.name':'tfs'}}}]},
                              {'to':[{'namespaceSelector':{'matchLabels':{'kubernetes.io/metadata.name':'kube-system'}}}],
                               'ports':[{'protocol':'UDP','port':53},{'protocol':'TCP','port':53}]}]}}
    return [service,policy,pod]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True); parser.add_argument('--base-image',required=True)
    parser.add_argument('--new-run',action='store_true'); args=parser.parse_args()
    if socket.gethostname()!='lima-transeuroogs-tfs': raise RuntimeError('Dedicated emulation VM required')
    release=verify(args.source)
    base=json.loads(kube('get','namespace','tfs','-o','json'))
    if base['metadata'].get('labels',{}).get('transeuroogs.lab')!='true': raise RuntimeError('Owned TeraFlow laboratory absent')
    old=json.loads(kube('get','namespace',NS,'--ignore-not-found','-o','json') or '{}')
    if old and (not args.new_run or any(old['metadata'].get('labels',{}).get(k)!=v for k,v in LABELS.items())):
        raise RuntimeError('Existing namespace requires an explicit new synthetic run; prior journals will be retained')
    if not args.base_image.startswith('localhost:32000/transeuroogs/device@sha256:') or len(args.base_image.rsplit(':',1)[1])!=64:
        raise RuntimeError('Use the pinned existing TeraFlow Device image')
    image='localhost:32000/transeuroogs/physical:'+release['source_revision'][:16]
    subprocess.run(['sudo','docker','build','--platform','linux/amd64','--build-arg','BASE='+args.base_image,'-f',str(args.source/'deploy/physical/Dockerfile'),'-t',image,str(args.source)],check=True)
    subprocess.run(['sudo','docker','push',image],check=True)
    inspect=json.loads(run(['sudo','docker','image','inspect',image]))[0]
    image=next(x for x in inspect['RepoDigests'] if x.startswith('localhost:32000/transeuroogs/physical@sha256:'))
    manifest=json.loads(run(['sudo','docker','buildx','imagetools','inspect','--raw',image]))
    if 'manifests' in manifest:
        child=next(x for x in manifest['manifests'] if x.get('platform',{})=={'architecture':'amd64','os':'linux'})
        image=image.split('@')[0]+'@'+child['digest']
    session='run-'+str(uuid.uuid4()); state=ROOT/'physical-state'/session; state.mkdir(mode=0o700,parents=True)
    subprocess.run([str(args.source/'bin/test-pki'),'--profile','physical','--out',str(state/'pki')],check=True,stdout=subprocess.DEVNULL)
    certs={name:(state/'pki'/name).read_bytes() for name in PKI_NAMES}
    # Only laboratory-owned objects and a new controller credential mount change.
    print(apply([{'apiVersion':'v1','kind':'Namespace','metadata':{'name':NS,'labels':LABELS}}]),end='')
    print(apply([{'apiVersion':'v1','kind':'PersistentVolumeClaim','metadata':{'name':'physical-state','namespace':NS,'labels':LABELS},
                  'spec':{'accessModes':['ReadWriteOnce'],'resources':{'requests':{'storage':'128Mi'}}}},
                 secret('physical-pki',NS,certs), secret('physical-controller','tfs',{name:certs[name] for name in ('ca.crt.pem','controller-sae.crt.pem','controller-sae.key.pem')})]),end='')
    before=json.loads(kube('-n','tfs','get','deployment/deviceservice','-o','json'))
    (state/'previous-device-template.json').write_text(json.dumps(before['spec']['template']))
    patch={'spec':{'template':{'metadata':{'annotations':{'transeuroogs.physical-session':session}},'spec':{
        'volumes':[{'name':'physical-controller','secret':{'secretName':'physical-controller'}}],
        'containers':[{'name':before['spec']['template']['spec']['containers'][0]['name'],
                       'volumeMounts':[{'name':'physical-controller','mountPath':'/run/transeuroogs/physical','readOnly':True}]}]}}}}
    kube('-n','tfs','patch','deployment/deviceservice','--type=strategic','-p',json.dumps(patch))
    print(kube('-n','tfs','rollout','status','deployment/deviceservice','--timeout=120s'),end='')
    if old: kube('-n',NS,'delete','pod/physical-lab','--ignore-not-found','--wait=true','--timeout=60s')
    print(apply(objects(image,session,release)),end='')
    record=dict(session=session,image=image,source_revision=release['source_revision'],git_revision=release['git_revision'],dirty=release['dirty'])
    (state/'installed.json').write_text(json.dumps(record,indent=2)+'\n')
    (ROOT/'physical-state'/'latest.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record))


if __name__=='__main__': main()
