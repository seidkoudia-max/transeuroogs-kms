# Development plan

This follows the staged [design discussion](https://chatgpt.com/share/6aa4058f-4374-83ed-b1ff-e6af5d5267f9).
Each milestone has a runnable demonstration and tests before the next adapter.
M0–M7 are engineering stages, not project calendar months or WP4 milestone IDs.

| Milestone | Deliverable | Status |
| --- | --- | --- |
| M0 | Repository, architecture, requirements, data/security models | Merged into main |
| M1 | Atomic Go core, memory repository, synthetic ingestion | Merged into main |
| M2 | Initial 014 profile, mTLS, two-SAE local lab, CI | Merged into main |
| M3 | Published 020 profile, durable async transfer, trusted relay, distinct-key multipath/failover | Merged into main |
| M4 | PostgreSQL material/metadata separation, operational PKI, audit/rate-limit hardening | Software baseline plus optional PKCS#11 wrapping and independent checkpoint witness implemented; physical HSM/site PKI, HA and deployment acceptance remain |
| M5a | Upstream EAGLE-1 014 client, durable paired ingestion and two-site service emulator with delayed offline relay | Implemented segmented synthetic profile; partner validation pending |
| M5b | SES deployment profile and external interoperability validation | Needs profile and partner test access; gateway authorisation is confirmed |
| M6 | LU/GR demonstration, then DE and IE deployments of the same KMS/adapter | Planned |
| M7 | Metadata foundation, evidence/policy and incident tracing, then metadata-only SDN-facing management | Local policies, signed command/protection history, provider-evidence adapter contract, receipts, bounded 015 agent and TeraFlow driver/reconciler implemented; SES evidence agreement, physical service provisioning and 021/023 integration pending; see [REMOTE_QCI_UPGRADES](REMOTE_QCI_UPGRADES.md) |

M2 acceptance: `make check` and `make demo`; the demo must verify 1,000 matching
keys, unique IDs, pool depletion, mTLS and rejection of a repeat slave delivery.
Docker Compose provides the same isolated test topology where Docker is available.

M3 acceptance: `make check`, `make demo`, and `make relay-demo`. The network
lab validates direct interworking and a six-node synthetic relay topology,
including route distribution, preflight failover and process restarts. See
[ETSI020_PROFILE](ETSI020_PROFILE.md) for the implemented limits.

The 2026-09-11 project clarification settles gateway authorisation, trusted-node
co-location and satellite ownership of offline relay. The public SES interface
supports an upstream 014 integration baseline. See
[EAGLE1_INTEGRATION](EAGLE1_INTEGRATION.md) for source references and the remaining
deployment parameters. An unknown deployment profile does not block M5a.

M5a acceptance: `make check`, `make demo`, and `make segmented-demo`. The new
upstream 014 client and repository preserve paired KIDs and local single delivery.
The separate-process demo checks delayed final-key availability, depletion,
three trust domains, role isolation, restart replay rejection and slave retrieval
while the master KMS is stopped. Unit tests cover model replenishment, expiry,
malformed/lost responses and interrupted durable intents. The application harness
carries selected KIDs; no inter-country KMS control link is required. These tests
model the central provider's service contract without reimplementing satellite
cryptography or establishing application-to-application authentication.

M5b repeats agreed acceptance against the SES test service using its actual
endpoint, identity, key and lifecycle profile. M4 operational persistence/security
hardening can progress alongside M5a and remains required before operational use.

The SDN-facing abstraction is part of the project scope. Static routes and the
two-site ingestion demo can operate without an external controller. Dynamic
management must be metadata-only and respect pinned transfer ownership.
The [WP4 planning discussion](https://chatgpt.com/share/6aa41edc-19c4-83eb-83a7-1b2608413d5a)
provides the wider project milestone context; the engineering stages above do
not replace its schedule.

## Operational and application increment

The foundation, 020 and segmented PRs (#1–#3) were reviewed and merged into
`main` on 2026-09-11. The next branch adds PostgreSQL snapshots across all three
repository modes, separate metadata/secret schemas, external wrapping-key
generations, checkpoint-based rejection of database rollback, operational CRLs,
CSR/credential validation, durable request auditing and identity rate limits.
See [OPERATIONS](OPERATIONS.md) for deployment and recovery boundaries.

A reference consuming application now supplies authenticated KID notification,
peer identity validation and standard TLS 1.3 PSK key confirmation, with durable
replay prevention. [APPLICATION_INTEGRATION](APPLICATION_INTEGRATION.md) documents
its library callback and remaining integration with a chosen business application.
This does not modify the SES-owned middle segment.

Acceptance adds `make app-test` and `make operational-demo` to the existing checks.
The latter creates a real isolated PostgreSQL cluster and runs two national KMS
processes, a synthetic provider and independent application processes. This
software increment does not complete real deployment milestone M6 or certify M5b.

## Metadata increments before deployment

[METADATA_PROFILE](METADATA_PROFILE.md) defines M7a (semantic model and history),
M7b (evidence exchange, initial policies and incident tracing) and M7c (management
integration). It maps required failure, race and authorisation checks to META
requirement IDs. [SES_METADATA_CHECKLIST](SES_METADATA_CHECKLIST.md) records the
provider questions, and [INCIDENT_TRACING](INCIDENT_TRACING.md) specifies exposure
intervals, partial coverage and separately authorised remediation.

The metadata runtime now atomically persists signed lifecycle observations in
local, segmented and relay repositories, exposes restricted mTLS summaries and
investigator history/query endpoints, and verifies offline signed evidence from
multiple nodes. `make metadata-demo` exercises two sites, restarts, authenticated
disclosure, evidence tampering and incident-to-delivery tracing. Relay tests cover
distinct-path isolation; real PostgreSQL tests cover history recovery and public
metadata separation. See [METADATA_RUNTIME](METADATA_RUNTIME.md) for limits.

M7 now adds locally enforced source, issuer, evidence, freshness, entitlement and
batch policies; scoped metadata-only management; signed command events; safe
route changes; and an opt-in TeraFlow v7 driver with durable policy reconciliation.
`make sdn-demo` checks the actual driver contract against a real local KMS over
mTLS. Captured 015 data passes validation against the published V2.1.1 YANG model.
The real TeraFlow v7 controller allocation lab is now deployed in a dedicated
Ubuntu/MicroK8s VM on the development Mac, using Rosetta for upstream amd64
containers. See the [lab acceptance record](../deploy/teraflow/ACCEPTANCE.md).

The [Luxembourg two-link lab](../deploy/luxembourg/README.md) extends this with
four synthetic endpoint processes across two logical link domains, interworking
at the shared JFK trusted site. It exercises relay recovery under geographic-link
outages and local allocation through the deployed controller. M6 is still planned:
no IDQ/QUKY equipment is connected. The new protected transport composes per-peer
014 link intake with inter-KMS relay in synthetic tests. Top-level segmented SES
final-key intake remains separate. The running Luxembourg lab has not been
upgraded to this transport; the separate [integrated service lab](../deploy/services/README.md)
now deploys it with dedicated journals and link providers. These tests do not
establish physical interoperability.

The new cross-cutting increment implements explicit
[OGS-domain key pools](KEY_POOL_DESIGN.md): immutable peer/service pool bindings,
pool-scoped authorization and lifecycle state, a synthetic three-segment mapping
test and metadata/SDN integration. P1–P4 have bounded runtime coverage; P5 actual
SES mapping/acceptance remains pending. These are not completed M5/M6 deployment
milestones. The pool model preserves the
existing SAE-based 014 interface and delegates provider pairing to EAGLE-1.

M7 remains partial: actual SES evidence translation/acceptance, signing
rotation/archive, bandwidth/priority scheduling, controller service provisioning
and agreed 021/023 draft integration require further increments. No SES
agreement, production acceptance, independent
conformance or paper-level interoperability is established by these tests.

## Remote-QCI protection increment (2026-09-12)

The [remote-QCI runtime](REMOTE_QCI_UPGRADES.md) implements typed pool bindings,
SES input gates, scoped signed provider evidence, incident holds/invalidation,
non-consuming reconciliation, application pool context and durable receipts,
protected terrestrial relay with per-peer 014 link keys, optional PKCS#11
wrapping and an independent checkpoint witness. `make federation-demo` adds
separate-process pool/incident/restart acceptance. The full remaining scope and
external inputs are recorded there; lifetime archival/signing rollover, real
SES/vendor acceptance, automatic HA and an agreed PQ profile remain outstanding.
This source increment does not alter the running TeraFlow lab or complete M6.

## SDN services increment (2026-09-13)

M7 adds opt-in catalog lifecycle across all KMS backends, independently authorized
adapter observations, 015 application/link CRUD and validated inventory/rates,
scoped durable change pages, TFS sampling and a recoverable multi-domain workflow.
`make sdn-services-demo` exercises two independent KMS processes and the pinned
TFS driver, including lost activation replies and restarts.
[SDN_SERVICES](SDN_SERVICES.md) records exact limits and missing inputs.
021/023 authoritative models are unavailable; wire integration, guaranteed QoS,
standard notifications/discovery and hardware adapters/acceptance remain pending.

## Integrated TeraFlow deployment (2026-09-13)

The [service lab](../deploy/services/README.md) deploys the four-node workflow
through TeraFlow NBI/Device, separate adapter/observer/controller identities,
independent protected 014 link providers, pool controls and signed metadata.
It preserves previous lab journals and publishes a reference-workflow service
record into the native Context/WebUI. Controller writes require proof of the
exact durable KMS commit. Acceptance covers lost activation, restarts, matching
delivery, durable incident holds and delivery with all TFS services stopped.
Interrupted consuming link-key requests remain uncertain; an explicit synthetic
recovery operation retires their transfers without recycling material.

The local cluster runs this integration; native ServiceService handlers,
authoritative cross-pool evidence correspondence, operational PostgreSQL/HSM/
witness deployment, HA and physical vendor/SES acceptance remain open. This
does not complete M6, full SDN provisioning or independent standards conformance.

## Physical emulation increment (2026-09-13)

The user-requested [Helmos–Windhof scenario](PHYSICAL_EMULATION.md) adds QNETSIM
DES geometry/channel models, a phase-encoded BB84 receiver model, conditional
QBER/rate budgets, sequential satellite contacts/offline pairing, 25 km and
30 km fibre links, buffer filling/overflow/expiry and application demand.
Three physically budgeted synthetic key sources feed a four-KMS protected
JFK–Windhof–Helmos–HellasQCI path. KMS acceptance covers matching delivery,
source outages, durable pool holds, replay and metadata-only telemetry.
The isolated native TeraFlow lab retains buffered endpoint keys for inspection.

This is an emulation extension to M5a/M7, not completion of M5b/M6. Numerical
capacity tokens and actual KMS custody are reported separately. SES optical
calibration, operational orbit/interfaces, finite/discrete-phase security
validation, continuous hardware ingestion and production isolation/HA remain
outstanding. It does not claim a complete EAGLE-1 implementation or a validated
closed-loop digital twin.
