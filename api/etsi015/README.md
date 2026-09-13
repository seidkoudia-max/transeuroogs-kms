# ETSI GS QKD 015 agent profile

Baseline: published GS QKD 015 V2.1.1, April 2022. Unmodified model files and
ETSI licence are in `upstream/`, copied from the
[official repository](https://forge.etsi.org/rep/qkd/gs015-ctrl-int-sdn), tag
`v2.1.1`, commit `f6abcfd5590356f02a3e0c434ebd4f75e25f825a`.
The two IETF type imports (RFC 6991, revision 2013-07-15) are from TeraFlow v7's
mock-node schema directory, commit `fb8707871eba26806cac7ac373c70b2bb5bd26fc`;
their embedded IETF licence notices are retained. `SHA256SUMS.json` records bytes.

| Model operation | Profile support |
| --- | --- |
| Node identity, software version, configured location | Read |
| Preconfigured external application identities and local/remote node UUIDs | Read, scoped to controller grants |
| Application `app_qos/ttl` | Read when configured; PUT positive values up to 2,678,400 seconds |
| Managed application status | Registered, paused and expired status when lifecycle is enabled |
| Interfaces, quantum links, SKR/ESKR | Local catalog; fresh independently acknowledged observations only |
| QBER | Project telemetry only; pinned-model `when` limitation described below |
| Create/update/delete applications and desired links | Opt-in, locally authorized catalog only |
| Bandwidth/jitter/priority, arbitrary hardware provisioning | Unsupported |
| Notifications, complete RESTCONF discovery/YANG library | Standard transport unsupported; project change pages and TFS sampling available |

The partial profile exposes RFC 7951 JSON at
`/restconf/data/etsi-qkd-sdn-node:qkd_node`, with module-qualified root resources
and identityrefs. GET supports the node and its immediate children, application
list entries (`qkd_app=<UUID>`), `app_qos` and `app_qos/ttl`. TTL is local storage
age, never generation freshness. A disabled project TTL constraint is omitted
from the 015 view; GET of that missing leaf returns 404.

The original PUT profile supports an existing application's TTL leaf, with content type
`application/yang-data+json` and body `{"etsi-qkd-sdn-node:ttl": 600}`.
Use `If-Match: "<revision>"` from GET and an `X-Command-ID` UUID for durable exact
replay. This **project-specific conditional-write profile** maps into the same
repository command mechanism as the management API; it is not an ETSI RPC.
Missing preconditions return 428, conflicting revision/payload returns 412.
The opt-in catalog CRUD extension is documented in
[SDN services](../../docs/SDN_SERVICES.md); other mutations return errors. GET requests
with query parameters or bodies are rejected in this bounded profile.

`tests/validate_sdn_yang.py` validates the pinned modules and captured live agent
data and rejects deliberately invalid data. Schema validation does not establish
complete RESTCONF implementation or independent ETSI conformance. 021/023 are
not implemented by placing project fields under this namespace. See
[SDN allocation](../../docs/SDN_ALLOCATION.md) for the project API and limitations.

The service increment adds registered application/interface/link reads and
conditional catalog CRUD. `qkdl_enable` is desired state and requires a separately
authorized adapter acknowledgement; it is not proof of device execution. The
pinned model rejects physical performance under its unqualified `PHYS` condition
with qualified JSON identityrefs, so QBER is retained only in project reports.
Both baseline and service-node captures are validated in CI.
