# Controller-integrated service deployment

The existing local TeraFlow v7 controller now hosts the TransEuroOGS service
workflow. This extends the allocation lab with managed application/link
lifecycle, independent adapter telemetry, pool and metadata policies, protected
terrestrial relay and incident controls. Use the TeraFlow WebUI at
[127.0.0.1:8080](http://127.0.0.1:8080/) with context/topology **admin**. The four
new devices and the QKD service have **[services synthetic]** in their names.

The topology is Windhof HITEC → JFK IDQ → JFK ThinkQuantum → Betzdorf SES.
Each endpoint has its own KMS, local pool ID, journal and signing credential.
Two additional seeded 014 services provide independent synthetic link keys for
Windhof–JFK and JFK–Betzdorf. Those transfers use the existing `qkd-jwe-v1`
profile, RFC 7516 JWE `dir/A256GCM`, and separate one-use link keys. JFK's local
trusted interworking uses the existing 020 profile over mTLS. None of these
names asserts a connection to installed QKD equipment or an EAGLE-1 receiver.

## What TeraFlow controls

All workflow mutations travel through TeraFlow's internal NBI → Device service
→ TransEuroOGS driver → KMS management API. A successful NBI response is
insufficient: `ControllerAdapter` verifies the exact durable KMS command,
actor and revision through a separate read-only observer identity. Observations
used by the workflow are fresh Device RPC reads, not cached Context records.

The reference orchestrator retains its pause → provision → configure → activate
intent on a PVC. After acceptance, the completed material-free intent is adopted
by the operator's separate PVC, without copying key-plane credentials. A dropped activation reply is recovered by replaying the same
command. This is coordination of independent commits, not an atomic distributed
transaction. Periodic adapter reports use another identity and durable sequences.

`services-operator` publishes fresh metadata into Context and a QKD service
record visible in WebUI. It also exposes an internal read-only JSON status on
port 8080. The service record identifies its reference-orchestrator owner: this
increment does not implement a native TeraFlow ServiceService provisioning
handler or automatic physical path computation. TeraFlow never receives key
material. Application retrieval, protected transfer, expiry and incident gates
continue locally while the controller is unavailable.

## State and authority

New KMS resources live in `transeuroogs-services`. The original
`transeuroogs-kms` and `transeuroogs-lux` namespaces and journals are preserved.
`tfs` contains the controller, `services-operator`, `services-adapter` and the
privileged synthetic acceptance worker `services-test`.

The controller certificate has catalog/policy authority; the observer has read
authority; the adapter can report telemetry; protection and application roles
are separate. Only the acceptance worker mounts all synthetic test roles.
KMS ingress is restricted by network policy and still requires mTLS, a trusted
CA, hostname verification and the expected URI identity. KMS containers use an
unprivileged UID, no service-account token and a read-only root filesystem.
Upstream controller HTTP/gRPC is internal plaintext in this isolated lab;
production controller authentication, authorization and TLS remain required.

All six KMS processes retain encrypted snapshot journals and signed metadata on
separate PVCs. A new Windhof journal starts with 64 synthetic application keys;
each link provider starts with 128 independent synthetic link keys. An existing
`state.enc` always starts with **zero** new keys. Image upgrades never reset
journals, replay consumed keys or change the immutable configuration binding.

VM files:

- `/opt/transeuroogs/service-release`: public source and native ARM64 binaries.
- `/opt/transeuroogs/services-state`: private PKI, signing credentials, image
  digests, configuration binding, acceptance checkpoints and evidence.
- `previous-device-template.json`: original Device pod template for rollback.
- Acceptance-worker PVC: exact link/workflow intents, metadata-only delivery
  receipts and explicit retirement plan; no exported application key material.

Test certificates, seeded source keys and service registrations have finite
24-hour lifetimes. Received relay keys have their own, potentially shorter,
local expiry. Restarting does not renew any lifetime. Adapter rates are fixed
synthetic observations, not measurements or continuing key generation. Keep
both Mac and guest disk space under observation; PVC requests are not quotas.

## Build and install against the existing lab

First establish the pinned [base TeraFlow lab](../teraflow/README.md). A fresh
base build needs substantially more disk space than a service overlay. On the
Mac, from the repository:

```sh
make check demo services-bundle
limactl copy .local/services-release.tar.gz transeuroogs-tfs:/tmp/services-release.tar.gz
limactl shell --workdir=/tmp transeuroogs-tfs mkdir -p /opt/transeuroogs/service-release
limactl shell --workdir=/tmp transeuroogs-tfs tar -xzf /tmp/services-release.tar.gz -C /opt/transeuroogs/service-release
limactl shell --workdir=/tmp transeuroogs-tfs python3 /opt/transeuroogs/service-release/deploy/services/build.py
limactl shell --workdir=/tmp transeuroogs-tfs python3 /opt/transeuroogs/service-release/deploy/services/deploy.py install
```

Set `GO=/absolute/path/to/go` if necessary. The bundle includes a SHA-256 file
manifest, a content fingerprint and Git revision/dirty status. The builder
checks the manifest, overlays pinned parent images and records the architecture
child digests selected for Kubernetes. It does not rebuild the large upstream
dependencies or prune existing images/PVCs. The installer rejects foreign
namespaces and configuration changes against existing journals, and validates
all six configurations before cluster mutation.

Installation leaves the periodic adapter stopped to keep telemetry revisions
from racing the initial orchestrator transaction. Wait for pods to be ready,
then run the deliberately disruptive synthetic acceptance inside the VM:

```sh
python3 /opt/transeuroogs/service-release/deploy/services/acceptance.py
python3 /opt/transeuroogs/service-release/deploy/services/verify-history.py
python3 /opt/transeuroogs/service-release/deploy/services/adopt-workflow.py
python3 /opt/transeuroogs/service-release/deploy/services/deploy.py start-adapter
```

The runner records each completed step. Repeating a completed delivery is a
no-op; an uncertain source or recipient response blocks automatic retry and
retains its receipt. It restarts KMS/provider/controller/worker pods, verifies
lost-activation recovery, tests a hold on keys not yet delivered to the remote
recipient, and tests delivery with all seven TeraFlow services stopped. Original
controller replica counts are saved before disruption and restored on exit or
on the next runner invocation after a crash.

An interrupted consuming 014 link request cannot safely be repeated. Acceptance
allows outstanding transfers to settle, then explicitly retires remaining
synthetic intents through the existing authenticated void protocol. It retains
the exact IDs before sending, checks the ready sets at both endpoints, requires
at least half the initial batch to remain usable, and verifies that retired
records hold no material and cannot be delivered. This is an explicit lab
recovery operation, not automatic production reconciliation. No failed key is
returned to any pool. See [the observed acceptance record](ACCEPTANCE.md).

The history verifier uses locally pinned public signing keys and `kms-metadata`
to verify event/page signatures and retained-history coverage. Its incident
report preserves gaps in correspondence between separate pool/namespace
histories. Matching KIDs alone do not establish authoritative cross-domain
provenance or an EAGLE-1 mapping.

## Inspect and operate

On the Mac:

```sh
limactl shell --workdir=/tmp transeuroogs-tfs sudo microk8s kubectl -n transeuroogs-services get pods
limactl shell --workdir=/tmp transeuroogs-tfs sudo microk8s kubectl -n tfs exec deployment/services-test -- python /opt/transeuroogs-services/runtime.py state
```

Inside the VM, a temporary loopback-only status forward can be run with:

```sh
sudo microk8s kubectl -n tfs port-forward service/services-operator 8082:8080 --address=127.0.0.1
```

The monitor marks failed/stale observations unavailable and checks application
registration expiry and incident holds. A policy-enabled service does not assert
available physical hardware, a guaranteed rate or successful application use.
Pause `services-adapter` while applying a new explicit multi-domain workflow:
its telemetry commits share the KMS revision sequence and can otherwise cause a
CAS conflict. Resolve the saved intent; never silently rebase an uncertain write.
The current deployment automatically runs observation, not new service changes.

Rollback stops the three new `services-*` workers and six new KMS deployments,
then restores the saved Device pod template. Retain PVCs and credentials. Do not
roll an older KMS binary over a journal with newly supported lifecycle state.
The original lab remains available; its finite test credentials/keys may expire.

## Deployment gates still open

The implemented profile and schema tests do not establish independent ETSI
015/020 conformance. Authoritative 021/023 models and wire integration, standard
event transport, native service handlers, QoS/admission scheduling and physical
path control remain open. IDQ Clarion KX/Q-KMS and ThinkQuantum QUKY require their
actual endpoints, identities, control/telemetry contracts and hardware tests.
ETSI 014 key retrieval alone does not specify those control operations.

SES must supply the EAGLE-1 interface agreement, pool/KID correspondence,
authentication/evidence and operational lifecycle semantics. Existing SES gates
remain explicit; this terrestrial topology does not simulate an approved SES
middle segment. Production PKI, PostgreSQL/PKCS#11/HSM and witness deployment,
HA, archive/signing rotation, controller security and site acceptance are separate
operational work. Their optional source implementations are not activated by
this snapshot-based local lab. M6 and operational acceptance remain incomplete.
