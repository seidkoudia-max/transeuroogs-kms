# SDN allocation integration

Implemented software increment, 2026-09-12. Use **TeraFlow SDN** as the controller
and add a TransEuroOGS policy application and KMS driver. Building a new general
SDN controller is outside this increment. The runnable local test exercises the
actual v7 driver contract against a KMS over mTLS. A real TeraFlow v7 controller
is also deployed in the isolated local Ubuntu/MicroK8s allocation lab; see the
[deployment acceptance record](../deploy/teraflow/ACCEPTANCE.md). This does not
extend the KMS profile to physical link/service provisioning.

## Responsibility and standards boundary

Each national KMS enforces the last committed local policy without a live
controller. Application retrieval and inter-KMS transfer remain separate from
management. The SES/EAGLE-1 segment still owns paired KIDs, OGS authentication
and offline satellite relay. Neither TeraFlow nor this adapter changes that
black-box segment. Cross-domain orchestration is optional; local retrieval
introduces no cross-country control dependency.

| Interface | Verified baseline | Implemented here |
| --- | --- | --- |
| ETSI GS QKD 015, SDN controller–node agent | Published V2.1.1, April 2022 | Bounded node/application reads and per-application local-storage TTL write; see [015 profile](../api/etsi015/README.md) |
| ETSI GS QKD 021, orchestration for interoperable KMS | Stable draft 0.0.1, 2025-12-02; public repository contains no model | No wire implementation; needs accessible agreed draft/model and profile |
| ETSI GS QKD 023, monitoring | Stable draft 0.0.6, 2026-06-08; draft document requires ETSI access | No wire implementation; project snapshot polling is not labelled 023 |
| TeraFlow SDN | v7.0.0, `fb8707871eba26806cac7ac373c70b2bb5bd26fc` | Opt-in Device driver and durable one-domain policy reconciler; local allocation cluster deployed |

Primary references: [015 publication](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/015/02.01.01_60/gs_qkd015v020101p.pdf),
[021 work item](https://portal.etsi.org/webapp/WorkProgram/Report_WorkItem.asp?WKI_ID=67987),
[021 public repository](https://forge.etsi.org/rep/qkd/gs021-orch-interop-sdn),
[023 work item](https://portal.etsi.org/webapp/WorkProgram/Report_WorkItem.asp?WKI_ID=69537),
[TeraFlow release 7](https://tfs.etsi.org/news/release-7/).
Published [018 V1.1.1](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/018/01.01.01_60/gs_QKD018v010101p.pdf)
is an orchestration reference, not a substitute claim of 021 implementation.

## Enforced policies

Rules apply to an ordered, preconfigured master/slave association. A controller
may pause local delivery, restrict source classes and issuers, require evidence,
set generation freshness and local storage age limits, cap request size, or
select a subset/order of locally configured relay peers. It cannot create
associations, add trust roots, invent source evidence, alter peer URLs, or obtain
keys, KIDs, tokens, fingerprints or protocol extensions through management.

The source classes are `synthetic`, `satellite`, `terrestrial`, `unknown`.
Locally generated synthetic material has a local generation observation;
the synthetic upstream 014 service supplies an unverified source claim with
unknown generation time. Relayed origin remains unknown. No runtime adapter
currently supplies verified satellite/terrestrial provenance. Requiring such
evidence therefore denies delivery; a controller cannot manufacture it by
changing a rule. `allow_satellite` is an additional local entitlement check,
not SES authorisation or proof of satellite origin.

Generation freshness uses a conservative clock bound; missing generation time,
missing clock uncertainty or unverified evidence fails a mandatory freshness
requirement. Local storage age uses collection intent and is distinct from
generation freshness. Zero age limits in the **project rule** disable that
constraint; positive limits are at most 31 days. Expiry always applies.
An empty issuer list means no additional issuer restriction. Rules must contain
all eight fields when submitted through the project command API.

Selection and delivery checks execute under the repository lock. Policy changes
between reservation and consumption take effect at consumption, for the entire
batch. Denial retains reservations until a later permitted delivery, explicit
invalidation or expiry; it never makes them available for another reservation.
Already consumed keys cannot be recalled. A delayed upstream response that
exceeds local TTL is cleared and known IDs remain invalid tombstones.

Relay route selection remains distinct-key round robin with pre-send failover.
A committed route change updates candidates for unsent records. A concurrent
probe must recheck the selected candidate at the durable transfer boundary.
Once `Sent` is committed, retries and void handling stay pinned to that peer,
including after restart. Delivery pause is not QKD generation control and does
not cancel or redirect an existing transfer. New quantum-path computation and
physical device provisioning are not implemented by this KMS adapter.

## Management API and recovery

Enable `sdn` together with durable `metadata` configuration. Each association
needs a stable application UUID and explicit local/remote SD-QKD node UUIDs.
Use a dedicated URI-SAN controller certificate, separate from applications,
investigators, upstream providers and peer KMEs. Permissions are scoped by
association and separately grant writes and route changes. Operational mode
also applies existing CRL checks, rate limits and durable request auditing.

| Method/path | Purpose |
| --- | --- |
| `GET /management/v1/capabilities` | Explicit project and standards coverage |
| `GET /management/v1/state` | Scoped rules, node revision and aggregate counts |
| `POST /management/v1/commands` | Complete rule replacement, local TTL or configured route change |

A command contains `command_id` (UUID), `expected_revision` (integer),
`association` and one or more permitted changes: `rule`, `routes`, or
`local_ttl_seconds`. A TTL delta and a complete rule cannot be combined.
Route updates require route authority and must remain in the configured
catalog. Destination-shared associations cannot use this route update profile.

The KMS compares revisions and commits command identity, actor, resulting rule,
key state and signed `allocation_changed` event in one encrypted snapshot.
Exact retries return the original result, including after restart. A conflicting
payload/actor or stale revision returns 409. Unknown/invalid input returns 400;
insufficient authority returns 403; storage/history capacity errors return 503.
Any uncertain persistence failure stops further delivery in that process.

Initial SDN configuration is bound to state. Enabling/disabling it on an existing
unmanaged snapshot or changing its bootstrap rules is rejected; use a fresh lab
namespace. No destructive automatic migration is provided. Controller grants
may be updated locally on restart; this does not rewrite historical authority.
Command history is bounded (configured `max_commands`, maximum 10,000), and
signed history obeys `metadata.max_events`. Rotation/archive is future work.

Snapshots distinguish eligible local delivery copies, available copies, reserved
copies, delivery commitments and in-flight counts by configured peer. A local
two-recipient repository can count two copies of the same key. These are neither
SKR measurements nor application receipts. Upstream inventory is `null` unless
known; management does not poll a provider or report its availability as zero.
Read-only operational observations may persist expiry in local/ingestion modes.

Policy events extend the existing signed metadata profile with an optional
`control` payload. Older events keep their signed encoding. Upgrade offline
verifiers before importing pages with control events. Investigator access is
still required for history; controllers receive only the command result and
aggregate state. PostgreSQL's coarse metadata schema excludes policy history.

## TeraFlow integration and acceptance

The upstream v7 default `QKDDriver2` uses `verify=False` and has incomplete
Set/Delete/Subscribe handling. The opt-in driver here checks TLS chain, hostname
and exact server URI before sending requests, limits bodies, follows no redirects,
does not retry mutations automatically, and reports unsupported actions.
It discovers configured applications using the published 015 model and accepts
project commands at TFS resource `/transeuroogs/allocation`.
`__transeuroogs_state__` returns scoped allocation observations.

`Reconciler(driver, outbox).reconcile(desired)` is a policy component to run above
the Device driver, not a new SDN controller. It compares desired rules/routes to
an authenticated metadata snapshot and persists an exclusive local outbox before
calling `SetConfig`. Lost results retain the exact command for replay. Conflicting
revision/intent, unavailable observations and corrupt outboxes require resolution;
they never cause blind overwrite. Use a private persistent outbox directory,
one worker/outbox per node, and retain it across policy-process restarts.
There is no distributed transaction across countries: report each node's outcome
and reconcile independently. Strict bandwidth guarantees, admission priority,
physical-path optimisation and multi-domain service rollback remain future work.

Run `make check`, `make demo`, `make sdn-demo`, existing relay/segmented/metadata
labs and `make operational-demo`. The SDN demo checks real TLS identity isolation,
policy changes, concurrent replay, restart, lost command replies, signed events,
controller-independent delivery and key replay rejection. Go tests cover unknown
provider evidence, TTL expiry after provider consumption, policy rechecks on
reservations, route/probe races, pinned uncertain sends and PostgreSQL recovery.
Validate the captured schema data separately:

```sh
python3 -m venv .local/sdn-venv
.local/sdn-venv/bin/python -m pip install -r tests/sdn-requirements.txt
.local/sdn-venv/bin/python tests/validate_sdn_yang.py .local/sdn-node.json
```

These are software/profile tests. Full TeraFlow service provisioning, real
controller failover, 021/023 models, real equipment telemetry, SES/IDQ interfaces
and independent conformance evidence remain separate acceptance work. See the
[deployment bundle](../deploy/teraflow/README.md).
