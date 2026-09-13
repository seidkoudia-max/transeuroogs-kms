"""Build tiny pinned image overlays, preserving old images and deployment state."""
import importlib.util
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess

ROOT = Path('/opt/transeuroogs')
SOURCE = ROOT / 'service-release'
STATE = ROOT / 'services-state'


def verify(source):
    release = json.loads((source / 'release.json').read_text())
    hashes = release['files']
    if hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest() != release['source_revision']:
        raise RuntimeError('Release manifest fingerprint mismatch')
    actual = {str(p.relative_to(source)) for directory in ('src', 'deploy/services', 'bin')
              for p in (source / directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}
    if actual != set(hashes): raise RuntimeError('Release has missing or unlisted source files')
    for name, digest in hashes.items():
        path = source / name
        if path.is_symlink() or not path.resolve().is_relative_to(source.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Release file verification failed: ' + name)
    return release


def run(args):
    return subprocess.check_output(args, text=True).strip()


def main():
    if socket.gethostname() != 'lima-transeuroogs-tfs': raise RuntimeError('Dedicated VM required')
    STATE.mkdir(mode=0o700, exist_ok=True)
    base = json.loads((ROOT / 'lab-state/controller-images.json').read_text())['device']
    kms_base = json.loads((ROOT / 'lab-state/kms-image.json').read_text())['image']
    for image in (base, kms_base):
        if not image.startswith('localhost:32000/') or '@sha256:' not in image: raise RuntimeError('Pinned local image required')
    release = verify(SOURCE)
    revision = release['source_revision']
    build = STATE / 'build' / revision; build.mkdir(parents=True, exist_ok=True)
    shutil.copytree(SOURCE / 'src/sdn/teraflow', build / 'teraflow', dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copytree(SOURCE / 'deploy/services', build / 'services', dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copy2(SOURCE / 'deploy/services/device-overlay.Dockerfile', build / 'Dockerfile')
    images = {'source_revision': revision, 'git_revision': release['git_revision'], 'dirty': release['dirty'], 'base_device': base, 'base_kms': kms_base}
    for kind, platform, parent in [('device', 'amd64', base), ('kms', 'arm64', kms_base)]:
        tag = 'localhost:32000/transeuroogs/' + kind + ':services-' + revision[:12]
        if kind == 'kms':
            shutil.copy2(SOURCE / 'bin/kms', build / 'kms')
            (build / 'KMS.Dockerfile').write_text('ARG BASE\nFROM ${BASE}\nCOPY kms /bin/kms\n')
        cmd = ['sudo', 'docker', 'build', '--platform=linux/' + platform, '--build-arg', 'BASE=' + parent,
               '--label', 'org.opencontainers.image.revision=' + release['git_revision'], '--label', 'transeuroogs.content-sha256=' + revision, '-t', tag,
               '-f', str(build / ('Dockerfile' if kind == 'device' else 'KMS.Dockerfile')), str(build)]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
        subprocess.run(['sudo', 'docker', 'push', tag], check=True, stdout=subprocess.DEVNULL)
        digest = json.loads(run(['sudo', 'docker', 'image', 'inspect', tag]))[0]['RepoDigests'][0]
        manifest = json.loads(run(['sudo', 'docker', 'buildx', 'imagetools', 'inspect', '--raw', digest]))
        if 'manifests' in manifest:
            child = next(m for m in manifest['manifests'] if m.get('platform', {}).get('architecture') == platform and m.get('platform', {}).get('os') == 'linux')
            digest = digest.split('@')[0] + '@' + child['digest']
        images[kind] = digest
    (STATE / 'images.json').write_text(json.dumps(images, indent=2))
    print(json.dumps(images))


if __name__ == '__main__': main()
