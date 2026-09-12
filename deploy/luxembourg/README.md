# Luxembourg two-link synthetic laboratory

This extends the [local TeraFlow lab](../teraflow/README.md) with four logical
KMS endpoints representing two vendor link domains at three sites:

```text
Windhof HITEC OGS       JFK Kirchberg trusted node          Betzdorf SES
IDQ Clavis endpoint -- IDQ endpoint | ThinkQuantum endpoint -- QUKY endpoint
       windhof            jfk-idq   |       jfk-tq              betzdorf
                 lab-relay         | ETSI 020       lab-relay
```

The serial path in [topology.json](topology.json) is
`windhof -> jfk-idq -> jfk-tq -> betzdorf`. ETSI 020 is confined to the two
co-located JFK endpoints. The geographic links use the existing synthetic
`lab-relay` transport over mTLS. Application master/slave roles select Windhof
and Betzdorf for this test; they do not specify optical transmitter/receiver
roles. JFK exposes no local application delivery identity. There is no alternate
route in this topology, so a failed link must recover before delivery can proceed.

All four endpoints are TransEuroOGS processes inside one local VM. Vendor names
identify the planned attachment sites; no IDQ or ThinkQuantum equipment is
connected, and no vendor firmware or optical interface is emulated. The
[QUKY brochure](https://www.thinkquantum.com/wp-content/uploads/files/Brochure_QUKY.pdf)
describes ETSI 014/004 key-delivery interfaces. The user's IDQ pair delivers
through Clarion KX/Q-KMS. These are inputs to future provider integration.
See the [acceptance record](ACCEPTANCE.md) for the observed local results.

The current runtime cannot combine upstream 014 ingestion and inter-KMS mode in
one process. This lab seeds synthetic end-to-end keys at Windhof and transfers
them over authenticated TLS; it does **not** obtain or consume independent QKD
link keys or implement a QKD-key-protected geographic relay. Actual vendor
ingestion, link-key accounting and an agreed relay construction remain work
before hardware acceptance. This test is not independent standards conformance.

## Run and inspect

Use the already installed VM with the four endpoints in `transeuroogs-lux`.
Start/stop the complete VM using the base lab runbook. On the Mac:

```sh
limactl start transeuroogs-tfs
limactl shell --workdir=/tmp transeuroogs-tfs sudo microk8s kubectl -n transeuroogs-lux get pods
limactl shell --workdir=/tmp transeuroogs-tfs sudo microk8s kubectl -n tfs exec deployment/lux-client -- python /opt/lux-test/check.py state
```

The `state` action reads policy revisions and aggregate counts without consuming
keys. In the [WebUI](http://127.0.0.1:8080/), select
**Context(admin):Topology(admin)**, then **Device**. The four devices have a
`[synthetic]` suffix and appear alongside the base lab's `LU-KMS`.
This is device inventory; it does not provision optical links or TFS services.
The NBI and key APIs remain internal to the cluster.

## Install in a fresh base lab

First complete the base lab runbook from this checkout, including compilation of
`test-pki` with the new `--profile=luxembourg` option. The base image's KMS supports
the required relay and management APIs; no additional controller image is needed.
Copy this public source directory to `/opt/transeuroogs/kms/deploy/luxembourg` if
updating an older base lab. Run inside the dedicated VM:

```sh
python3 /opt/transeuroogs/kms/deploy/luxembourg/deploy.py
python3 -u /opt/transeuroogs/kms/deploy/luxembourg/acceptance.py
```

Installation leaves the four endpoints stopped so acceptance can hold the first
link down before the initial batch is created. It refuses a second installation
after its marker exists. Each endpoint has its own KME certificate, signing key,
encrypted journal and PVC. Ingress allows only adjacent endpoints and the lab
Device/test clients, followed by application-level mTLS authorization. The
existing LU-KMS deployment and its controller certificate mount are preserved.

The dedicated controller identity can manage allocation but has no key-plane or
route-write rights. The separate privileged test client holds synthetic SAE,
investigator, controller and Windhof KME credentials to exercise positive and
negative identity checks. This credential layout is for the test harness only.
Private material stays under `/opt/transeuroogs/lux-lab-state`, Kubernetes Secrets
and private volumes. Do not copy these into the repository or acceptance logs.

## Acceptance and recovery

[acceptance.py](acceptance.py) controls these phases:

1. Hold the first link down; assert no source delivery, including after restart.
2. Connect the first link, keep Betzdorf stopped, observe pending relay material
   at JFK, restart the JFK endpoints, and assert the source still cannot deliver.
3. Connect Betzdorf and wait for all 64 end-to-end acknowledgements.
4. Onboard four devices through the real TeraFlow NBI/Device service and check
   application, controller, investigator and adjacent-peer authorization.
5. Pause Betzdorf through TeraFlow, test blocked delivery, then require evidence
   and reject unknown received provenance. Resume and compare matching keys.
   Exact policy retries must increment only Betzdorf's revision once.
6. Retrieve matching selected keys at Betzdorf while Windhof is stopped; restart
   all endpoints and reject already delivered IDs.
7. Stop all seven TFS deployments and complete another matching pair delivery
   under the persisted local policies. Restore the controller on exit.
8. Compare all 64 KIDs across investigator histories, ensure acknowledged JFK
   records hold no material, and compare control events to policy revisions.

Three independent receipts each compare two 256-bit synthetic keys, for six
end-to-end application deliveries. Only private KIDs and SHA-256 comparisons are
persisted in test receipts; key bytes and fingerprints are never printed. These
comparisons are test evidence, not an application authentication protocol.

The runner checkpoints completed steps in `lux-lab-state/acceptance.json` and
can resume a failed non-delivery step. If interrupted during a master/slave
delivery it refuses automatic retry. Inspect `/state/private/<label>.json` in
the test client and the signed histories before advancing a checkpoint manually.
An `*-intent` receipt alone does not prove receipt by an application. Keep such
keys burned or uncertain; never delete journals, reset PVCs, or reseed to repair
a failed test. A completed acceptance run returns without delivering again.

Windhof seeds 64 keys **only once**. Their TTL and allocation freshness limit
are **one hour**; certificates last 24 hours. Restarts preserve state and create
zero new keys. Expiry fails closed, so this is a bounded test, not a continuously
replenished service. Preserve the expired namespace for evidence; a subsequent
batch needs an explicitly separate lab identity/state or a reviewed ingestion
increment. Do not erase consumed-key tombstones to refresh the display.

## Next hardware increment

For both paired vendor services, record the actual HTTPS endpoints, firmware/API
version, CA and identity mapping, SAE IDs and local roles, key sizes/KID format,
capacity/expiry behavior, retry semantics and a safe test window. Configure
credentials through the deployment secret mechanism, not source files or chat.
Obtain each vendor's operating profile rather than assuming brochure-level 014
compatibility specifies all of these details.

Validate each pair independently before integrating provider ingestion and
QKD-protected relay accounting. Then repeat the JFK authorization, matching KID,
single-delivery, outage/restart and allocation tests with the approved hardware
profile. Signed provider evidence remains unavailable: received provenance is
explicitly `unknown`, and evidence-required policies intentionally block it.
Physical service provisioning, telemetry, multi-domain reconciliation and
agreed 021/023 interfaces remain outside this increment.
