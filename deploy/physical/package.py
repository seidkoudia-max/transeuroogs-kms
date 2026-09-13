"""Package public physical-lab source, precomputed reports and Linux binaries.

The separate user-owned QNETSIM dependency and all credentials stay outside.
"""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    output = Path(sys.argv[1]); files = {}
    for directory in ('emulator/physical', 'src/sdn/teraflow', 'deploy/physical'):
        for path in (ROOT/directory).rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts:
                files[str(path.relative_to(ROOT))] = path
    files['emulator/eagle1-kms/demo.py'] = ROOT/'emulator/eagle1-kms/demo.py'
    for path in (ROOT/'.local/physical/helmos-windhof').glob('*.json'):
        if path.name == 'report.json' or path.name.endswith('-permit.json'):
            files['data/'+path.name] = path
    for name in ('kms','physical-source','test-pki','kms-metadata'):
        files['bin/'+name] = ROOT/'.local/physical/linux'/name
    hashes = {name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in sorted(files.items())}
    release = dict(files=hashes, source_revision=hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest(),
                   git_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                   dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip()))
    output.parent.mkdir(parents=True,exist_ok=True)
    with tarfile.open(output,'w:gz') as tar:
        for name,path in files.items(): tar.add(path,arcname=name,recursive=False)
        data = json.dumps(release,indent=2).encode(); info=tarfile.TarInfo('release.json'); info.size=len(data)
        tar.addfile(info,io.BytesIO(data))
    print(json.dumps(dict(bundle=str(output),source_revision=release['source_revision'],dirty=release['dirty'])))


if __name__ == '__main__': main()
