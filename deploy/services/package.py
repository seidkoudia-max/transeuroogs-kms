"""Create a public-source/binary release bundle; never include lab credentials."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    output = Path(sys.argv[1]); output.parent.mkdir(parents=True, exist_ok=True)
    files = {}
    for directory in ('src', 'deploy/services'):
        for path in (ROOT / directory).rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc':
                files[str(path.relative_to(ROOT))] = path
    for name in ('kms', 'kms-metadata', 'test-pki'):
        files['bin/' + name] = ROOT / '.local/services-bin' / name
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(files.items())}
    fingerprint = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
    release = {'source_revision': fingerprint, 'git_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
               'dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip()), 'files': hashes}
    with tarfile.open(output, 'w:gz') as archive:
        for name, path in sorted(files.items()): archive.add(path, arcname=name, recursive=False)
        raw = json.dumps(release, indent=2).encode(); info = tarfile.TarInfo('release.json'); info.size = len(raw)
        archive.addfile(info, io.BytesIO(raw))
    print(json.dumps({'bundle': str(output), 'content_sha256': fingerprint, 'git_revision': release['git_revision']}))


if __name__ == '__main__': main()
