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
| M4 | PostgreSQL material/metadata separation, operational PKI, audit/rate-limit hardening | Implemented software baseline on operational branch; site PKI, HA/HSM and deployment acceptance remain |
| M5a | Upstream EAGLE-1 014 client, durable paired ingestion and two-site service emulator with delayed offline relay | Implemented segmented synthetic profile; partner validation pending |
| M5b | SES deployment profile and external interoperability validation | Needs profile and partner test access; gateway authorisation is confirmed |
| M6 | LU/GR demonstration, then DE and IE deployments of the same KMS/adapter | Planned |
| M7 | Metadata foundation, evidence/policy and incident tracing, then metadata-only SDN-facing management | Local policies, signed command history, bounded 015 agent and TeraFlow driver/reconciler implemented and locally tested; full controller deployment, provider attestation and 021/023 integration pending; see [SDN_ALLOCATION](SDN_ALLOCATION.md) |

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
The full controller cluster is not deployed: local disk capacity is insufficient.

M7 remains partial: provider attestation ingestion, signing rotation/archive,
application usage receipts, incident holds/remediation, bandwidth/priority
scheduling, controller service provisioning and agreed 021/023 draft integration
require further increments. No SES agreement, production acceptance, independent
conformance or paper-level interoperability is established by these tests.
