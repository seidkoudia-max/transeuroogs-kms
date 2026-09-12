# Metadata and incident runtime v1

Implemented software subset, 2026-09-12. All acceptance uses synthetic keys.
This is the project's `transeuroogs-metadata-v1` profile. It does not establish
ETSI metadata conformance, an SES interface agreement or production readiness.
The wider milestone and remaining policies are in [METADATA_PROFILE](METADATA_PROFILE.md).

## Runtime boundary

`src/internal/metadata` wraps the shared durable-store interface. Each repository
projects its lifecycle snapshot into material-free records. The wrapper appends
signed observations under `Provenance` and commits the combined encrypted snapshot
through the existing single store operation. It publishes its in-memory history
only after that operation succeeds. There is no independent metadata dual write.

This works with local persistent storage, segmented ingestion and terrestrial
020 relay, using either their encrypted lab journals or the operational PostgreSQL
store. PostgreSQL's existing public SQL projection stays coarse; rich history and
its private attempt-alias map remain inside the restricted encrypted snapshot.
HTTP adapters do not issue SQL. No SDN controller or cross-country KMS control
connection is needed. Offline exports are an authorised investigation workflow.

Metadata save, signing, capacity or clock-rollback failure poisons the wrapper;
key operations and metadata queries then fail closed until recovery. A lost
commit response may leave a committed delivery event without delivered bytes.
The lifecycle tombstone stays authoritative after restart.

## Enable on fresh synthetic state

Build the helper and provision separate laboratory signing credentials outside Git:

```sh
mkdir -p .local/metadata .local/bin
chmod 700 .local/metadata
go build -o .local/bin/kms-metadata ./src/cmd/kms-metadata
.local/bin/kms-metadata keygen \
  --private .local/metadata/lu-signing.pem \
  --public .local/metadata/lu-verification.pem
```

`keygen` uses Go's P-256 generator and creates new mode-0600 PKCS#8/PKIX PEM files;
it never overwrites existing files. Signing credentials are separate from TLS
credentials. The private file must be a regular file with mode 0600. Protect and
retain it with the state; losing it prevents reopening that history.

Add this object to a valid KMS configuration, using absolute paths at deployment:

```json
{
  "metadata": {
    "domain": "lab-lu",
    "issuer": "urn:transeuroogs:kme:lu",
    "namespace": "lab-lu-gr-20260912",
    "credential_id": "lab-lu-metadata-v1",
    "signing_key_file": ".local/metadata/lu-signing.pem",
    "state_dir": ".local/metadata/lu-state",
    "max_events": 10000,
    "clock_uncertainty_ms": null,
    "readers": {
      "urn:transeuroogs:investigator:lab": [
        {"master": "SAE-LU", "slave": "SAE-GR"}
      ]
    }
  }
}
```

Use an investigator certificate issued by the local trust domain with that exact
URI SAN. Investigators must have separate identities from the configured application
SAEs. Every reader pair must be in the node's configured associations. Ordinary
applications retain their existing local identity restrictions and cannot enumerate
history. The operational profile applies its existing CRLs, rate limits, concurrency
limits and durable request audit to these additional reader identities.

`state_dir` is required only for local mode without PostgreSQL. Segmented/relay
mode reuses its existing configured journal location; PostgreSQL mode uses the
operational database namespace, wrapping keys and checkpoint. Metadata namespace
is a key-identity namespace, distinct from the PostgreSQL storage namespace.
Configure the same metadata namespace and ordered pair on nodes describing the
same unchanged keys, and distinct issuer/signing identities per node. Cross-node
matching requires that exact namespace/KID/pair binding and an explicit trust entry.

`clock_uncertainty_ms: null` or an omitted value means unknown, not zero. Only
configure a numeric bound (0–60000 ms) when justified by the lab/site clock model.
The demos use zero as a synthetic timing assumption, not a production claim.

Enable this on **fresh synthetic state**. Existing unannotated snapshots are
rejected because they cannot establish past history. Migration is not implemented;
do not delete deployed state to enable metadata. Once a durable snapshot contains
`Provenance`, opening that same snapshot through an unwrapped repository is rejected.
Changing to a different/ephemeral repository does not migrate or preserve history.
Synthetic provisioning is allowed only for fresh metadata state.

The profile, domain, issuer, namespace, credential/public key, event limit and clock
bound are bound to that history. Changing those fields requires a future migration
or rotation procedure. Reader scopes can change independently. This version has no
signing-key rollover, archive, garbage collection or capacity-increase migration.
Consumed-key tombstones are never reclaimed. Plan a bounded lab run and export
evidence before capacity is exhausted.

## Recorded semantics

Every event has a random UUID, issuer/domain, local sequence, UTC recording time,
clock uncertainty, actions and one key observation or upstream-attempt observation.
The previous signed-event digest and previous event for that key provide linkage.
Typed projections exclude key bytes, material-derived hashes, reservation tokens,
private credentials, arbitrary extensions and request bodies. Public attempt
references are independently generated UUID aliases, never reservation tokens.

Key observations contain the unchanged KID, ordered pair, configured namespace,
source/evidence classification, generation time or null, collection-intent time,
local expiry, local role/recipient state, logical material custody, configured
upstream/next identity and transfer/ready/void/uncertainty flags. States describe
committed observations; they are not a live allocation authorization.

Only the local synthetic source records its own generation timestamp. The synthetic
upstream profile reports `synthetic` / `unverified_claim`, with generation time
unknown. Relayed source evidence remains unknown where there is no authenticated
origin assertion. Collection and local expiry are never relabelled as authoritative
generation time or provider validity. No SES origin/relay-completion claim is verified.

`holding_material` / `material_cleared` describe the logical repository snapshot.
They cannot establish erasure from heap copies, TLS buffers, backups or compromised
hosts. Upstream bytes received and burned between snapshots get a possible intake
interval bounded by request/commit observations. A consumed right records a KMS
delivery commitment; it does not establish application receipt or business use.

## Read-only API

The API is on the same TLS listener and is mounted only when metadata is enabled.
It leaves the existing 014/020 key endpoints and strict extension handling unchanged.
Only verified mTLS URI identities are accepted; identity headers have no effect.

| Method and path | Audience | Response |
| --- | --- | --- |
| GET `/metadata/v1/keys/{uuid}` | Local SAE in that ordered pair, or scoped investigator | Signed restricted key summary, own recipient state for SAEs; no topology or history |
| GET `/metadata/v1/events?after=0&through=0&limit=64` | Investigator | Signed page of signed events filtered to the reader's configured pairs |
| POST `/metadata/v1/trace` | Investigator | Read-only local incident report with coverage and evidence references |

Responses use JSON, `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
Unrecognised identities receive 401, application history/trace access 403, missing
or unauthorised keys 404, invalid requests 400, unsupported methods 405, trace
content type 415, oversized trace bodies 413, and unavailable history 503. GET
bodies, duplicate/unknown query fields and unknown/duplicate/aliased JSON members
are rejected. Queries cannot supply arbitrary URLs, reader scopes or key material.

Event pages contain `page` and compact `jws`. The signed page binds profile,
issuer/domain/namespace, audience URI, association scope, history start, observation
cutoff, watermark, cursor interval and events. Start with `after=0` and `through=0`;
retain the returned `watermark`, then request `after=page.next&through=watermark`
until `page_complete` is true. A fixed nonzero watermark has a fixed time cutoff.
`limit` is 1–64, default 64; a byte budget may return fewer events. Sequence gaps
can reflect authorised filtering, so scoped page assertions also carry coverage.
An empty history (watermark zero) is one page; there is nothing to continue.

Example trace body (omit clock uncertainty when unknown; explicit null is rejected
in HTTP requests):

```json
{
  "incident_id": "d7eb9be8-70b1-4d71-9de9-a53e8410a518",
  "subject": "urn:transeuroogs:kme:lu",
  "kind": "material_exposure",
  "start": "2026-09-12T10:00:00Z",
  "end": "2026-09-12T10:01:00Z",
  "clock_uncertainty_ms": 0,
  "limit": 100
}
```

`subject` identifies a node/issuer; batch/device/session selectors are unsupported.
Kinds are `material_exposure` and `issuer_compromise`. Start is inclusive and end
exclusive, with a maximum 31-day window. Limit is 1–128 (omitted/zero uses 100).
The API evaluates a snapshot of local history; offline export verification supplies
multiple nodes. The trace report itself is unsigned; keep its signed evidence.

## Signed offline evidence

The implementation uses compact JWS through the pinned
[go-jose library](https://github.com/go-jose/go-jose), ES256/P-256 only. Protected
headers are exactly `alg`, `kid` and `typ: transeuroogs-metadata+jws`. Embedded keys,
remote key URLs, alternate algorithms and additional headers are rejected.
Payloads use the exact versioned JSON representation in `metadata/model.go`:
declaration field order, explicit nulls where declared, omitted optional fields,
Go JSON string/time encoding. Verification rejects duplicate/unknown/aliased members
and alternative encodings. This is a narrow project format, not a general JSON
canonicalization standard or a negotiated partner format. Preserve signed payloads.

Export each authorised signed-page response as one compact NDJSON line, using the
same audience URI across independently authenticated site connections. Transfer
exports through the approved investigation process and keep their access restricted.
The CLI never fetches remote references or contacts a key service. Supply a JSON
array of trust entries, one per issuer, with fields:

```json
[
  {
    "issuer": "urn:transeuroogs:kme:lu",
    "domain": "lab-lu",
    "namespace": "lab-lu-gr-20260912",
    "credential_id": "lab-lu-metadata-v1",
    "public_key_file": ".local/metadata/lu-verification.pem",
    "pairs": [{"master": "SAE-LU", "slave": "SAE-GR"}],
    "valid_from": "2026-09-12T00:00:00Z",
    "valid_until": "2026-09-13T00:00:00Z",
    "revoked": false
  }
]
```

Add an independently authorised entry/public key for each further node. Obtain
verification keys through the site trust process, not from the evidence itself.
The example times are a lab acceptance window, not prescribed certificate validity.
Exact issuer, domain, namespace, credential, pair, audience and recording-time
authority are verified before tracing. Revoked entries reject all their evidence,
including historical evidence; finer historical revocation is not implemented.

```sh
.local/bin/kms-metadata trace \
  --trust .local/metadata/trust.json \
  --query .local/metadata/incident.json \
  --evidence .local/metadata/signed-pages.ndjson \
  --audience urn:transeuroogs:investigator:lab \
  --out .local/metadata/new-report.json
```

The helper creates a new mode-0600 report and never overwrites an existing file.
Exact evidence replay is deduplicated; altered/conflicting replay is rejected.
Missing pages or key predecessors yield partial coverage. Signatures authenticate
local statements, not their physical truth or completeness after issuer compromise.
Independently retained exports remain necessary for comparison; coordinated rollback
of all trusted state/checkpoints/exports is outside the model. Signatures are
classical, not post-quantum.

## Investigation limits and next work

Findings are `affected` under the supplied incident and clock assumptions,
`possibly_affected` with uncertain timing/intake, or `unknown` with missing history.
Exposure is evaluated over logical custody intervals, so an old key held during
an incident is included. All known recipient commitments for the exact key/pair
are included, even earlier ones that may matter for retrospective confidentiality.
Distinct keys on other multipath routes acquire no inferred dependency.

Reports state supplied issuer/namespace/pair coverage, retained time, watermark,
gaps and unresolved attempts. SES history remains unknown. Missing upstream evidence
must cover the exact namespace, pair and key before it can exclude exposure.
Unknown-ID attempts retain their alias and uncertainty without fabricated KIDs.
`complete_within_supplied_scope` never grants global clearance. An empty finding
list with gaps is not an unaffected conclusion. Logical custody cannot exclude
exposure in unmodelled memory, backup or application locations.

History is bounded by `max_events` (1–100000) and a 64 MiB combined snapshot limit,
whichever is reached first. Every save copies/serializes history; this is a bounded
single-writer lab baseline, not an indexed high-throughput event store. Offline
input is at most 64 MiB, 10000 pages, 100000 unique events and 64 trusted issuers;
each NDJSON line is under 128 KiB. Page payloads are budgeted to 48 KiB before
their outer signature. Trace bodies are at most 8 KiB and queries inspect at most
100000 events. Large trace results can exceed the operational guard's existing
128 KiB response cap and fail closed; use smaller investigation scope or offline
evidence. No automatic retention, report pagination or archive service exists.

The operational profile audits investigator requests through its existing durable
guard. The basic journal lab profile has no separate durable inquiry audit. Neither
profile implements investigator-driven holds, remediation, application notification
or remote revocation. [SDN_ALLOCATION](SDN_ALLOCATION.md) adds local
freshness/source/issuer/entitlement policy checks, signed command history and
metadata-only management with a TeraFlow driver. Provider attestation ingestion,
inline 014/020 metadata negotiation, business session receipts, signing rotation,
full controller deployment and 021/023 integration remain subsequent increments.

Run `make check`, `make demo`, `make relay-demo`, `make segmented-demo`,
`make metadata-demo` and the operational acceptance suite. The metadata demo uses
separate test signing keys and TLS trust domains, preserves 64 paired keys, restarts
both KMSs and verifies evidence/incident correlation at both recipients. See the
[verification map](../tests/README.md) for failure, replay, scope and race cases.
