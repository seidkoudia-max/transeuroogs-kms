# Development plan

This follows the staged [design discussion](https://chatgpt.com/share/6aa4058f-4374-83ed-b1ff-e6af5d5267f9).
Each milestone has a runnable demonstration and tests before the next adapter.
M0–M7 are engineering stages, not project calendar months or WP4 milestone IDs.

| Milestone | Deliverable | Status |
| --- | --- | --- |
| M0 | Repository, architecture, requirements, data/security models | Implemented in foundation branch |
| M1 | Atomic Go core, memory repository, synthetic ingestion | Implemented in foundation branch |
| M2 | Initial 014 profile, mTLS, two-SAE local lab, CI | Implemented in foundation branch |
| M3 | Published 020 profile, durable async transfer, trusted relay, distinct-key multipath/failover | Implemented in ETSI 020 branch |
| M4 | PostgreSQL material/metadata separation, operational PKI, audit/rate-limit hardening | Planned |
| M5a | Upstream EAGLE-1 014 client, durable paired ingestion and two-site service emulator with delayed offline relay | Implemented segmented synthetic profile; partner validation pending |
| M5b | SES deployment profile and external interoperability validation | Needs profile and partner test access; gateway authorisation is confirmed |
| M6 | LU/GR demonstration, then DE and IE deployments of the same KMS/adapter | Planned |
| M7 | Metadata-only management and required SDN-facing abstraction; controller integration | Planned; external controller is optional for static lab operation |

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
