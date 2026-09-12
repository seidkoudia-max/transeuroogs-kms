"""Load the actual pinned upstream base class without the controller services.

Only package namespaces are supplied here; the driver contract itself is the
unmodified TeraFlow v7 _Driver.py. This is a contract test, not a deployed TFS.
"""
import importlib.util
import hashlib
import json
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_driver():
    root = ROOT / "tests/upstream/teraflow-v7"
    for name, digest in json.loads((root / "SHA256SUMS.json").read_text()).items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError("Pinned TeraFlow interface changed")
    for name in ("device", "device.service", "device.service.driver_api"):
        module = types.ModuleType(name)
        module.__path__ = []
        sys.modules[name] = module
    name = "device.service.driver_api._Driver"
    spec = importlib.util.spec_from_file_location(name, ROOT / "tests/upstream/teraflow-v7/_Driver.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    sys.path.insert(0, str(ROOT / "src/sdn"))
    from teraflow.QKDDriver import QKDDriver
    assert issubclass(QKDDriver, module._Driver)
    return QKDDriver
