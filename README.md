# TransEuroOGS KMS

Interoperable quantum key management for TransEuroOGS, developed from the
[agreed design](https://chatgpt.com/share/6aa4058f-4374-83ed-b1ff-e6af5d5267f9).

The synthetic-key laboratory now includes a Go lifecycle core, ETSI GS QKD
014 application delivery, an asynchronous ETSI GS QKD 020 V1.1.1 profile,
durable inter-KMS transfer, and trusted hop-by-hop relay with distinct-key
multipath routing and pre-transfer failover.

This is a laboratory prototype. The relay links use classical mTLS with
synthetic keys. Real QKD link protection, SES interoperability, site deployment
acceptance and independent standards conformance remain outstanding.

The agreed EAGLE-1 target is an authorised gateway inside each local trusted node,
collecting keys through the SES ground service's published ETSI 014 interface.
The satellite owns offline relay. A synthetic upstream client, durable ingestion and
black-box service emulator are implemented; see [EAGLE-1 integration](docs/EAGLE1_INTEGRATION.md)
for the confirmed responsibilities and outstanding deployment profile.

The [physical emulation](docs/PHYSICAL_EMULATION.md) connects JFK–Windhof OGS
(25 km fibre), EAGLE-1's simulated paired-key service, and Helmos OGS–HellasQCI
(30 km fibre). QNETSIM models the pass, phase-BB84 rates, QBER and buffer
filling/expiry; four real KMS processes exercise protected end-to-end delivery.
`make physical-test` and `make physical-demo` run the single-pass regression.
`make physical-timeline-demo` adds three passes, independent Gamma–Gamma and
fibre Raman/loss fluctuations, four separate QBER/SKR panels and pointwise
observations of all four KMSs. It establishes 32 application keys after each
pass, verifies 80 matching deliveries and retains 16 buffered keys at completion.
An interactive replay and
[native TeraFlow laboratory](deploy/physical/README.md) expose the results.
All key material is synthetic; the rate model is conditional and not a validated
finite-key security calculation.

## Run the laboratory

Requires Go 1.27+ and Python 3.10+ for the original demos. PostgreSQL uses the
pinned pgx driver. The operational/application acceptance suite additionally
requires PostgreSQL binaries and Python 3.13+ with OpenSSL PSK support.

```sh
make check
make demo
make relay-demo
make segmented-demo
make metadata-demo
make sdn-demo
```

`make demo` generates a temporary development PKI under `.local/pki/`, starts a
local KMS, ingests 1,000 synthetic 256-bit keys, and checks that SAE-LU and
SAE-GR receive matching IDs and bytes without repeat delivery. It prints only
counts and verification results. No key material is committed or logged.

`make relay-demo` runs separate KMS binaries and encrypted journals. It checks
four direct ETSI 020 keys, 24 end-to-end keys distributed 12/12 across two
trusted relay paths, and eight keys through a surviving path. Both SAE endpoints
recover after SIGKILL before delivery and restart after consumption to verify
persistence and replay protection.
See [the 020 profile](docs/ETSI020_PROFILE.md) for topology and failure semantics.
Static routing works without an SDN controller.

`make segmented-demo` verifies 64 matching keys through two local upstream 014
services, three independent test CAs, role isolation, delayed availability and
restart replay rejection. The slave retrieves matching keys while the master
KMS is stopped. The harness supplies application KID notification; it does not
implement an application authentication protocol or SES satellite cryptography.

`make operational-demo APP_PYTHON=python3.14` creates an isolated PostgreSQL
cluster, verifies operational storage/recovery controls and runs authenticated
application KID notification and TLS 1.3 key confirmation through two national
KMS processes. `make app-test APP_PYTHON=python3.14` runs the application tests.
See [operations](docs/OPERATIONS.md) and [application integration](docs/APPLICATION_INTEGRATION.md).
The operational profile supports separate metadata/material access, external
wrapping-key rotation, CRLs, audit records and rate limits. Site PKI issuance,
HSM/HA deployment validation and integration with a chosen business application
remain explicit operational inputs.

`make metadata-demo` adds signed lifecycle history to the two-site segmented
exercise, exports evidence under separate investigator identities, and verifies
an offline incident trace against both national histories. It checks restricted
application summaries, restart recovery and rejection of tampered evidence.
The same runtime supports local persistence and terrestrial relay. See the
[metadata runtime](docs/METADATA_RUNTIME.md) for configuration, API and CLI usage.

`make sdn-demo` runs the TeraFlow v7 driver contract against a local KMS over
mTLS. It verifies metadata-based allocation, controller identity isolation,
durable policy reconciliation and restart/replay behavior. The KMS also exposes
a bounded ETSI 015 V2.1.1 agent profile; captured data is validated against the
published YANG model in CI. A real TeraFlow v7 allocation lab now runs in an
isolated local Ubuntu/MicroK8s VM. Physical service provisioning and 021/023 draft
integration remain pending. The new `make sdn-services-demo` tests catalog
application/link lifecycle, separate synthetic adapter telemetry, TFS sampling
and two-KMS orchestration recovery; see [SDN services](docs/SDN_SERVICES.md).
The [integrated service deployment](deploy/services/README.md) now runs this
workflow through the real TeraFlow NBI/Device services, with four isolated KMSs,
pool controls and two independent synthetic 014 link-key providers. See
[SDN allocation](docs/SDN_ALLOCATION.md) and the [base lab](deploy/teraflow/README.md).

The [Luxembourg two-link lab](deploy/luxembourg/README.md) adds four synthetic
endpoint KMSs for Windhof–JFK (IDQ) and JFK–Betzdorf (ThinkQuantum QUKY), with
ETSI 020 interworking inside the trusted JFK site. Its controller-driven tests
cover both link failures, relay recovery, matching delivery, policy enforcement
and controller outage. Its original state is preserved. The separate integrated
service lab deploys the protected transport with 014 link keys, lifecycle and
incident controls; actual vendor hardware acceptance remains pending. See
[remote-QCI protection](docs/REMOTE_QCI_UPGRADES.md).

To leave a local ETSI 014 server running for experiments:

```sh
make pki
go run ./src/cmd/kms --synthetic-keys 1000
```

In another terminal, retrieve metadata:

```sh
curl --cacert .local/pki/ca.crt.pem \
  --cert .local/pki/sae-lu.crt.pem --key .local/pki/sae-lu.key.pem \
  https://localhost:8443/api/v1/keys/SAE-GR/status
```

Synthetic provisioning is opt-in at startup. Without `--synthetic-keys`, the
pool starts empty. Configuration is in `deploy/config/local.json`. Runtime
certificate paths default to `.local/pki/` and can be supplied with `--pki-dir`.
The server always requires mTLS; there is no plaintext or header-identity mode.

With Docker Compose installed:

```sh
make compose-demo
docker compose down -v
```

Compose runs an isolated lab and generates its test PKI in an ephemeral volume.
The KMS is not published on a host port. `down -v` removes that lab volume.

## Repository

- `src/internal/core/`: domain types and repository contract.
- `src/internal/storage/`: atomic memory and persistent repository implementations.
- `src/internal/postgres/`: transactional snapshots, metadata isolation, audit and rollback checkpoints.
- `src/internal/metadata/`: signed local observations, bounded evidence verification and incident tracing.
- `src/internal/metapi/`: mTLS metadata summaries and investigator API.
- `src/internal/wrapping/`: external file-ring encryption and protector interface.
- `src/application/`: authenticated notification and standard TLS PSK reference SAE.
- `src/internal/etsi014/`: application HTTP adapter and wire models.
- `src/internal/etsi020/`: asynchronous peer protocol, strict validation and mTLS client.
- `src/internal/relay/`: durable transfer lifecycle and outbox.
- `src/internal/ingest/`: segmented upstream ingestion and local delivery journal.
- `src/internal/upstream/`: explicit upstream profile and role configuration.
- `src/internal/durable/`: shared encrypted single-writer laboratory snapshots.
- `src/internal/eaglelab/`: delayed paired-service outcome model.
- `src/internal/peering/`: configured peer identities, transport modes and routes.
- `src/internal/security/`: verified certificate identity and TLS configuration.
- `src/cmd/`: KMS, metadata evidence utility, enrollment and test-PKI tools.
- `emulator/`: synthetic-source and SAE laboratory documentation/harness.
- `tests/`: integration tests and requirement traceability.
- `api/etsi014/openapi.json`: application laboratory contract.
- `api/etsi020/`: pinned ETSI upstream OpenAPI contract and license.
- `docs/`: architecture, data model, security, profiles, and development plan.
- `deploy/`, `.github/`: reproducible lab and continuous integration.

Read [ARCHITECTURE](docs/ARCHITECTURE.md), [REQUIREMENTS](docs/REQUIREMENTS.md),
and [DEVELOPMENT_PLAN](docs/DEVELOPMENT_PLAN.md) before extending the service.

The metadata increment implements signed local history and read-only incident
tracing. [METADATA_PROFILE](docs/METADATA_PROFILE.md) distinguishes this executable
subset and the new local policies from pending provider evidence and full SDN
controller deployment.
The [SES interface checklist](docs/SES_METADATA_CHECKLIST.md) remains unanswered;
the [incident tracing specification](docs/INCIDENT_TRACING.md) preserves the three
trust segments and treats provider history and application receipt as unknown.

The original local 014 fixture uses memory and loses its state on restart.
Network mode retains transfer and delivery tombstones in encrypted local state.
Never load production key material. Lost SAE responses burn delivery rights;
applications must not automatically retry key retrieval. Peer transfer retries
are handled separately by the durable outbox.

The [remote-QCI protection increment](docs/REMOTE_QCI_UPGRADES.md) adds OGS pool
bindings, explicit pending SES inputs, provider evidence, incident actions and
receipts, QKD-link-protected terrestrial relay, optional HSM wrapping and an
independent checkpoint witness. Run `make federation-demo` for the synthetic
three-segment pool/incident test. External interoperability and the documented
continuous-operation/PQ/HA boundaries remain open.
