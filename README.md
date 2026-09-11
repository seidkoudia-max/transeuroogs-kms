# TransEuroOGS KMS

Interoperable quantum key management for TransEuroOGS, developed from the
[agreed design](https://chatgpt.com/share/6aa4058f-4374-83ed-b1ff-e6af5d5267f9).

The synthetic-key laboratory now includes a Go lifecycle core, ETSI GS QKD
014 application delivery, an asynchronous ETSI GS QKD 020 V1.1.1 profile,
durable inter-KMS transfer, and trusted hop-by-hop relay with distinct-key
multipath routing and pre-transfer failover.

This is a laboratory prototype. The relay links use classical mTLS with
synthetic keys; real QKD link protection, EAGLE-1 integration, production
hardening and independent standards conformance remain future work.

## Run the laboratory

Requires Go 1.27+ and Python 3.10+. The Go service has no third-party dependencies.

```sh
make check
make demo
make relay-demo
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
- `src/internal/storage/`: atomic memory implementation.
- `src/internal/etsi014/`: application HTTP adapter and wire models.
- `src/internal/etsi020/`: asynchronous peer protocol, strict validation and mTLS client.
- `src/internal/relay/`: durable transfer lifecycle, encrypted journal and outbox.
- `src/internal/peering/`: configured peer identities, transport modes and routes.
- `src/internal/security/`: verified certificate identity and TLS configuration.
- `src/cmd/`: KMS binary and test-PKI generator.
- `emulator/`: synthetic-source and SAE laboratory documentation/harness.
- `tests/`: integration tests and requirement traceability.
- `api/etsi014/openapi.json`: application laboratory contract.
- `api/etsi020/`: pinned ETSI upstream OpenAPI contract and license.
- `docs/`: architecture, data model, security, profiles, and development plan.
- `deploy/`, `.github/`: reproducible lab and continuous integration.

Read [ARCHITECTURE](docs/ARCHITECTURE.md), [REQUIREMENTS](docs/REQUIREMENTS.md),
and [DEVELOPMENT_PLAN](docs/DEVELOPMENT_PLAN.md) before extending the service.

The original local 014 fixture uses memory and loses its state on restart.
Network mode retains transfer and delivery tombstones in encrypted local state.
Never load production key material. Lost SAE responses burn delivery rights;
applications must not automatically retry key retrieval. Peer transfer retries
are handled separately by the durable outbox.
