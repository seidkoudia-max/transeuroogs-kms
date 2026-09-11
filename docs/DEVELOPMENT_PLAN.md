# Development plan

This follows the staged [design discussion](https://chatgpt.com/share/6aa4058f-4374-83ed-b1ff-e6af5d5267f9).
Each milestone has a runnable demonstration and tests before the next adapter.

| Milestone | Deliverable | Status |
| --- | --- | --- |
| M0 | Repository, architecture, requirements, data/security models | Implemented in foundation branch |
| M1 | Atomic Go core, memory repository, synthetic ingestion | Implemented in foundation branch |
| M2 | Initial 014 profile, mTLS, two-SAE local lab, CI | Implemented in foundation branch |
| M3 | Published 020 contract, persistent transfer state, async emulator, recovery tests | Planned |
| M4 | PostgreSQL material/metadata separation, operational PKI, audit/rate-limit hardening | Planned |
| M5 | EAGLE-1 interface agreement and external interoperability lab | Needs partner profile/access |
| M6 | LU/GR demonstration, then DE and IE adapters | Planned |
| M7 | Metadata-only management and optional SDN/orchestration | Planned |

M2 acceptance: `make check` and `make demo`; the demo must verify 1,000 matching
keys, unique IDs, pool depletion, mTLS and rejection of a repeat slave delivery.
Docker Compose provides the same isolated test topology where Docker is available.

The next bounded implementation is to pin the 020 schema and define its
durable transaction model. Do not expand the current same-node fixture into a
fictional peer protocol. Integrate one real external system at a time.
