# TransEuroOGS KMS

Interoperable quantum key management for TransEuroOGS, developed from the
[agreed design](https://chatgpt.com/share/6aa4058f-4374-83ed-b1ff-e6af5d5267f9).

The first milestone is a runnable **synthetic-key laboratory**: a Go lifecycle
core, atomic in-memory repository, an initial ETSI GS QKD 014 profile, mTLS,
and two test applications that obtain corresponding keys exactly once.

This is an early prototype, not a production KMS or a claim of ETSI conformance.
ETSI 020, real EAGLE-1 connectivity, durable storage, and multi-domain delivery
are subsequent milestones. The local demo places both SAE delivery records in
one KMS; it does not simulate a satellite or implement inter-KMS distribution.

## Run the laboratory

Requires Go 1.27+ and Python 3.10+. The Go service has no third-party dependencies.

```sh
make check
make demo
```

`make demo` generates a temporary development PKI under `.local/pki/`, starts a
local KMS, ingests 1,000 synthetic 256-bit keys, and checks that SAE-LU and
SAE-GR receive matching IDs and bytes without repeat delivery. It prints only
counts and verification results. No key material is committed or logged.

To leave a server running for experiments:

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
- `src/internal/etsi014/`: HTTP adapter and wire models.
- `src/internal/security/`: verified certificate identity and TLS configuration.
- `src/cmd/`: KMS binary and test-PKI generator.
- `emulator/`: synthetic-source and SAE laboratory documentation/harness.
- `tests/`: integration tests and requirement traceability.
- `api/etsi014/openapi.json`: machine-readable laboratory API contract.
- `docs/`: architecture, data model, security, profiles, and development plan.
- `deploy/`, `.github/`: reproducible lab and continuous integration.

Read [ARCHITECTURE](docs/ARCHITECTURE.md), [REQUIREMENTS](docs/REQUIREMENTS.md),
and [DEVELOPMENT_PLAN](docs/DEVELOPMENT_PLAN.md) before extending the service.

Memory state, including duplicate-ID tombstones, is lost on restart. Never
load production key material into this implementation. Lost responses burn
delivery rights; clients must not automatically retry key retrieval.
