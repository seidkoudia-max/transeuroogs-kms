# Requirements

The baseline is a laboratory milestone, with synthetic data only. Requirement
IDs below describe project behavior; they are not ETSI clause identifiers.

| ID | Required behavior | Verification |
| --- | --- | --- |
| CORE-001 | Validate UUID, exact 256-bit size, ordered association and timestamps | core/storage tests |
| CORE-002 | Reject duplicate IDs including terminal tombstones | storage tests |
| CORE-003 | Reserve complete batches atomically under concurrency | race tests |
| CORE-004 | Deliver once per authorized recipient; reject token/ID replay | storage and integration tests |
| CORE-005 | Enforce expiry and invalidation before all deliveries | deterministic clock tests |
| CORE-006 | Preserve batch atomicity on insufficient inventory and partial failures | storage tests |
| CORE-007 | Copy material at repository boundaries; exclude it from metadata and ordinary formatting | storage/core tests |
| API-001 | Provide the documented 014 GET/POST profile and defaults | HTTP tests |
| API-002 | Reject invalid size/count, mandatory extensions, duplicate IDs, malformed or oversized JSON | HTTP tests |
| API-003 | Report only inventory for the authorized ordered pair | HTTP tests |
| SEC-001 | Require verified mTLS, TLS 1.3 minimum and configured URI SAN identity | live TLS tests |
| SEC-002 | Enforce association authorization including each requested ID | HTTP/storage tests |
| SEC-003 | Avoid material in logs, diagnostics, management or generic serialization | core tests, demo output |
| SEC-004 | Bound memory lifetime capacity, requests and HTTP timeouts | storage/HTTP tests, configuration |
| LAB-001 | Generate synthetic material only when explicitly enabled | source/CLI tests and demo |
| LAB-002 | Verify 1,000 unique matching deliveries and denied replay | `make demo` |
| NET-001 | Async 020 versions, transfer, ACK, void and strict bounded wire profile | 020 HTTP/TLS tests |
| NET-002 | Commit transfer/consumption before side effects; persist tombstones and ACK outbox | relay recovery tests |
| NET-003 | Match remote SAE keys across trusted hops; distribute distinct IDs over routes | network demo and relay tests |
| NET-004 | Fail over only before first send; pin uncertain transfers across restarts | fault-injected relay tests |
| NET-005 | Cascade void/expiry, reject revival and preserve optional extension values | relay tests |
| NET-006 | Encrypt local state; exclusive writer; fail closed on corruption or write failure | journal tests |
| LAB-003 | Independent TLS processes, both relay paths, outage and restart | `make relay-demo` |
| OPS-001 | Run format, vet, race tests, build and demo in CI | GitHub Actions |

See [tests/README](../tests/README.md) for the test map. New features require
positive and negative test cases. Independent 020 conformance, operational
security/HA and real EAGLE-1 interoperability are not established by this table.

## Segmented EAGLE-1 laboratory requirements

These implement the selected trusted-segment model using a synthetic provider.
They do not establish actual SES interoperability. See
[EAGLE1_INTEGRATION](EAGLE1_INTEGRATION.md).

| ID | Required behaviour | Verification |
| --- | --- | --- |
| EAGLE-001 | Collect final keys as a locally authenticated upstream 014 gateway; keep the local application delivery role separate | `make segmented-demo`, 014 client TLS/profile tests |
| EAGLE-002 | Preserve provider KIDs with durable gateway/application binding and no duplicate terrestrial relay | Segmented demo, collision and restart tests |
| EAGLE-003 | Honour the provider's final-key availability, with satellite relay treated as a black box | Delayed service demo and replenishment model test |
| EAGLE-004 | Preserve ambiguous collection outcomes, local expiry and single delivery across failures | Lost-response, interrupted intent, crash, replay and expiry tests |
| EAGLE-005 | Configure upstream identities, trust, role and local retention; reject unknown profiles and conflicting modes | Configuration tests and independent-CA demo |
| EAGLE-006 | Use one adapter implementation with independently configured national endpoints | LU/GR segmented demo; DE/IE deployment validation pending |
| EAGLE-007 | Restrict each profile to one local/upstream pair and preserve per-association master/slave roles | Configuration, repository role and local identity tests |
| MGMT-001 | Provide an SDN-facing metadata abstraction independent of key-plane operation; expose no key material | Planned; management interface not implemented |

Application notification of the selected KID is supplied by the harness. The
reference application now supplies notification, peer authentication and TLS
key confirmation in the operational increment; segmented KMS authentication does not implement
that application protocol. The central segment's OGS authentication and key
pairing are assumed provider responsibilities for these tests.

## Operational and consuming-application software

| ID | Required behaviour | Verification |
| --- | --- | --- |
| OPS-002 | Commit encrypted PostgreSQL snapshots with separately readable metadata and restricted audit access | Real PostgreSQL lifecycle/privilege tests |
| OPS-003 | Fence competing writers, reject database rollback and fail closed on uncertain persistence | PostgreSQL restart, rollback and connection-loss tests |
| OPS-004 | Manage wrapping-key generations outside the database and retain decryptability across rotation | Key-ring tests and operational demo |
| SEC-005 | Require current signed issuer CRLs and validate issued credentials/CSR identities | Operational security and enrollment tests |
| SEC-006 | Bound per-identity traffic and concurrent work; commit audit before key response | Guard fault and rate-limit tests |
| APP-001 | Authenticate application peers and notify the selected unchanged KID over mTLS | Operational separate-process demo |
| APP-002 | Use standard TLS key confirmation, rejecting mismatched material or session identity | Native OpenSSL PSK tests |
| APP-003 | Bind identities, ordered pair, KID and expiry; reject replay after restart/concurrency | Application ledger and notification tests |

The reference application implements these APP requirements. Integration with
a specific operational encryptor/business application uses its confirmed-stream
callback and still needs that application's deployment profile. See
[OPERATIONS](OPERATIONS.md) and [APPLICATION_INTEGRATION](APPLICATION_INTEGRATION.md).
