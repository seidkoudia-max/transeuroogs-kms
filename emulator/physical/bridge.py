"""Load an explicitly installed, hash-pinned QNETSIM/QUASAR snapshot.

No fallback DES, network downloads or imports from report-controlled paths.
The user's simulator source remains a separate dependency, not republished here.
"""
import argparse
import hashlib
import importlib
import json
from pathlib import Path
import shutil
import sys

HERE = Path(__file__).resolve().parent
DEFAULT = HERE.parents[1] / '.local/physical/qnetsim'


def verify(root):
    root = Path(root).resolve()
    manifest = json.loads((HERE / 'qnetsim.lock.json').read_text())
    for name, digest in manifest['files'].items():
        path = root / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Missing or changed QNETSIM dependency: ' + name)
    return manifest


def install(source, destination=DEFAULT):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    manifest = verify(source)
    if destination.exists():
        verify(destination)
        return
    destination.mkdir(parents=True)
    for name in manifest['files']:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    verify(destination)


def load(root=DEFAULT):
    root = Path(root).resolve()
    manifest = verify(root)
    for name in ('qnetsim.framework.core.des', 'studies.quasar_matera_helmos.run_study', 'channels.fso'):
        module = sys.modules.get(name)
        if module and not Path(module.__file__).resolve().is_relative_to(root):
            raise RuntimeError('QNETSIM module namespace already belongs to another installation')
    sys.path[:0] = [str(root / 'standalone_bundle'), str(root)]
    des = importlib.import_module('qnetsim.framework.core.des')
    physics = importlib.import_module('studies.quasar_matera_helmos.run_study')
    return des, physics, manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--destination', type=Path, default=DEFAULT)
    args = parser.parse_args()
    install(args.source, args.destination)
    print('Verified QNETSIM dependency installed; no simulator output or key material copied.')
