"""Validate 015 schemas and captured synthetic agent data; not conformance certification."""
import json
import hashlib
import pathlib
import re
import subprocess
import sys
from yangson import DataModel
from yangson.enumerations import ContentType

ROOT = pathlib.Path(__file__).resolve().parents[1]
schema = ROOT / "api/etsi015/upstream"
for name, digest in json.loads((schema / "SHA256SUMS.json").read_text()).items():
    if hashlib.sha256((schema / name).read_bytes()).hexdigest() != digest:
        raise RuntimeError("Pinned model changed")
files = sorted(schema.glob("*.yang"))
subprocess.run([str(pathlib.Path(sys.executable).with_name("pyang")), "-p", str(schema)] + [str(f) for f in files], check=True)
modules = []
for file in files:
    source = file.read_text()
    modules.append({"name": file.stem, "revision": re.search(r"revision\s+[\"']?(\d{4}-\d{2}-\d{2})", source)[1], "namespace": re.search(r'namespace\s+[\"\']([^\"\']+)', source)[1], "conformance-type": "implement" if file.stem.startswith("etsi-qkd-") else "import"})
model = DataModel(json.dumps({"ietf-yang-library:modules-state": {"module-set-id": "etsi015-v2.1.1", "module": modules}}), [str(schema)])
data = json.loads(pathlib.Path(sys.argv[1]).read_text())
model.from_raw(data).validate(ctype=ContentType.all)
# Ensure the validator actually rejects a malformed identityref and unknown leaf.
for bad in ("bad_identity", "invented_leaf"):
    invalid = json.loads(json.dumps(data))
    node = invalid["etsi-qkd-sdn-node:qkd_node"]
    if bad == "bad_identity":
        node["qkd_applications"]["qkd_app"][0]["app_type"] = "etsi-qkd-node-types:INVENTED"
    else:
        node["satellite_key_material"] = "synthetic-negative-fixture"
    try:
        model.from_raw(invalid).validate(ctype=ContentType.all)
    except Exception:
        pass
    else:
        raise RuntimeError("Validator accepted invalid schema data")
print("PASS: pinned ETSI 015 schemas and captured agent JSON, including negative cases")
