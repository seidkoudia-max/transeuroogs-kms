# TransEuroOGS metadata milestone

Status: M7a runtime and the evidence/incident-query portion of M7b implemented,
2026-09-12. This is a project profile, not a new ETSI standard or evidence of
standards conformance. [METADATA_RUNTIME](METADATA_RUNTIME.md) specifies the
executable subset. Policy-based allocation, provider evidence ingestion,
incident holds and SDN/controller integration remain pending.

The research proposal [In QKD, Key Metadata is Key, v1](https://arxiv.org/abs/2608.11502)
informs this design through its Section IV and appendix. Its sample envelopes
and algorithms are illustrative; they are not an agreed SES interface.

## Architecture and increments

Retain the three trust segments, unchanged provider KIDs, per-association
master/slave roles and one national KMS implementation. EAGLE-1 owns OGS
authentication, pairing and offline relay. Terrestrial 020 relay remains a
separate mode, with distinct keys on each multipath route. This increment adds
no splitting, derivation or inter-country KMS control dependency. Keep metadata
logic in domain services/repositories, independent of HTTP and SDN.

The runtime now adds signed, material-free observations to the same encrypted
snapshot as each lifecycle transition. It supports local persistence, segmented
ingestion and terrestrial relay. A separate authenticated metadata API preserves
the existing 014/020 wire contracts. Their inline metadata extensions and actual
provider evidence ingestion remain future work; unsupported fields remain strict.

M7 in [DEVELOPMENT_PLAN](DEVELOPMENT_PLAN.md) is refined as follows. These are
engineering increments, not new calendar milestones or replacements for M5b.

| Increment | Deliverable | Acceptance |
| --- | --- | --- |
| M7a | Versioned local-observation model; key/event/issuer references; explicit unknowns; durable local event history | Implemented; model, persistence, recovery, race and access-control tests |
| M7b | Verified evidence exchange, initial policies, incident tracing and controlled disclosure | Signed offline exchange and read-only tracing implemented; allocation policies and remediation pending |
| M7c | Metadata-only management API and selected SDN/controller adapter | Pending; the incident API does not implement controller orchestration |

Synthetic M7a/M7b can proceed before deployment. Real claims and cross-domain
trust require the [SES answers](SES_METADATA_CHECKLIST.md). M4 operational
hardening and M5b partner acceptance remain separate gates.

## Shared semantics

The tables and policies below describe the full intended profile. Fields absent
from the executable subset are unsupported, not implicitly verified or enforced.
In particular, generation and relay-completion assertions from SES, application
session receipts and arbitrary transformation relations are not imported yet.

Use the project profile identifier `transeuroogs-metadata-v1`. Explicitly
negotiate its transport mapping; do not use another organisation's private
enterprise number or present a lab namespace as registered.

| Concept | Meaning |
| --- | --- |
| Key reference | Issuing namespace, unchanged KID and ordered association binding. KID alone does not establish globally trusted identity. |
| Issuer | Configured domain/node/service, credential reference and permitted claim types. TLS access is not claim authority. |
| Event | Immutable ID, issuer, operation, referenced keys/events, occurred time and recorded time. Record locally observed operations or explicitly attribute provider claims. |
| Operations | Generation, provider release, ingestion, reservation, delivery commitment, relay acceptance/forwarding/acknowledgement, expiry and invalidation. |
| Relations | Typed links to predecessor events and opaque transaction/application session references. Forwarding preserves the key identity. |
| Source | Synthetic, satellite, terrestrial or unknown, with issuer and evidence status. A configured source label is not verified origin. |
| Generation time | Authoritative time or conservative interval; unknown when unavailable. Whole-key freshness requires the oldest bound of all contributing material. |
| Relay completion | Provider assertion that offline relay produced the final paired key. Distinct from generation and collection. |
| Recorded time | Local durable recording time; never substitute it for generation time. |
| Validity | Separate provider validity, local retention, evidence validity and credential validity; delivery obeys all applicable limits. |
| Evidence status | Unknown, local observation, unverified claim or verified authorised-issuer claim. Verification authenticates a statement, not physical quantum generation. |
| Coverage | Reported domains/time range, retained history and unresolved references; partial history is never complete coverage. |

Use UTC, explicit precision and bounded clock uncertainty. Freshness uses the
oldest plausible generation bound. Missing clock/component information cannot
be silently treated as fresh or zero uncertainty. Metadata excludes raw keys,
material-derived fingerprints, private credentials and arbitrary request bodies.

Keep the core's existing duplicate-KID rejection. Namespacing metadata does not
authorise duplicate UUIDs from two providers inside the same repository; reject
that ambiguity until a separately reviewed core change supports it.

## History and transaction boundary

Commit each lifecycle transition and its event or durable event-outbox item
atomically, before bytes or network side effects leave the repository. Do not
implement a best-effort logger or independent dual-write metadata database.
Extend the repository persistence contract; HTTP handlers must not issue SQL.

Exact event replay is idempotent. Reusing an event ID with conflicting content
fails. Corrections append references to earlier statements instead of editing
history. Retries reuse the committed event. Delivery commitment records that
the KMS burned its right; application receipt and business use require separate
authenticated assertions. Unknown-ID requests and lost responses remain
uncertain rather than acquiring invented KIDs or success records.

Bound history size, query work and evidence retention. Full storage fails closed
for operations requiring an event. Never reclaim consumed-key tombstones to
make space. Signed records do not establish completeness: sequence coverage,
checkpoints and independently retained exports are needed to detect omissions.
Existing database/checkpoint host-compromise limitations still apply.

## Trust, transport and disclosure

Use established signature containers and maintained cryptographic libraries;
pin allowed algorithms, issuer authority, versions and size bounds. Do not
invent a signing protocol or implement the paper's sample cryptography verbatim.
Signing credentials remain outside Git and separate from ordinary access roles.
Define issuer rotation, historical revocation and incident overrides explicitly.
A valid signature from an unauthorised or compromised issuer is insufficient.

Implement a reviewed 014 key/container extension or authenticated metadata
reference/API, with strict parsing. Reference retrieval uses configured services
only, no caller-selected URLs or redirects, and bounded depth/size. 020 extension
preservation is only transport: semantic verification and event generation need
explicit support. Reject unknown mandatory requirements before allocation where
locally decidable. Report unsupported optional claims without claiming success.
Clients that do not negotiate metadata retain their existing wire contract.

Applications see their own association's statements and policy results. Local
operators see authorised local history. Federation peers receive agreed views
or references; controllers receive only authorised inventory, alarms and policy
outcomes. Metadata can reveal topology and business relationships even without
key bytes, so ordinary consumers must not enumerate unrelated records.

## Initial policy and failure scope

This section is the next policy increment; these allocation checks are not yet
implemented. The current runtime records and queries observations without
changing key eligibility or accepting caller-supplied policy requirements.

Start with maximum generation age, allowed source/issuer, and configured local
entitlement to scarce satellite material. Evaluate policy atomically with
selection and recheck time-sensitive conditions and incident holds at delivery.
Unknown mandatory claims fail closed. Policy-satisfying inventory is distinct
from total inventory. Authentication rate limits are not key entitlement quotas.

If evidence arrives only in an upstream consuming response, rejecting it may
burn the key. Persist the rejection and terminal ID, withhold delivery and do
not retry consumption or return material to a pool. Metadata-write uncertainty
also withholds delivery. Preserve batch atomicity and pinned-route ownership.

Jurisdiction, device assurance classes, billing, delegation, resource prediction,
zero-knowledge proofs and arbitrary rule languages are later extensions. Reject
mandatory requests for capabilities outside the implemented profile.

## Acceptance requirements

| ID | Required check | Current coverage |
| --- | --- | --- |
| META-001 | Preserve KID/pair across LU/GR; reject namespace/pair conflicts and conflicting event replay. | Implemented for project exports; real provider namespace agreement pending |
| META-002 | Old generation with recent ingestion fails freshness; missing time, uncertainty or component coverage fails a mandatory freshness policy. | Pending allocation-policy increment |
| META-003 | Reject forged/altered evidence, wrong issuer authority, unsupported algorithm/version and invalid trust status. | Implemented ES256 allowlist and offline verification; partner trust profile pending |
| META-004 | Crash at intent, upstream response, event commit and delivery; no key leaves without committed history and no uncertain key returns to inventory. | Atomic snapshot and ambiguous-commit tests; two-site restart demo; broader filesystem/power-loss campaign pending |
| META-005 | Concurrent reservations, consumption and incident holds preserve batch atomicity and per-recipient single delivery. | Delivery race and ambiguous commit covered; incident holds pending |
| META-006 | Test negotiated 014 metadata and 020 transport, including unknown mandatory requirements and legacy clients. | Separate metadata API implemented; inline 014/020 mapping and requirements negotiation pending |
| META-007 | Trace custody-window exposure to downstream keys and application commitments; distinguish affected, possible and unknown. | Implemented for unchanged namespaced keys and KMS delivery commitments; business-use receipts pending |
| META-008 | Under partition, retention gaps or query limits, report partial coverage instead of global clearance. | Missing pages, unknown clocks/provider and scope gaps covered; archive service pending |
| META-009 | Deny cross-association reads/actions and verify metadata/logs contain no material. | Read-only API role/scope tests and projection redaction tests; no remediation API |
| META-010 | A non-entitled caller cannot consume locally known satellite inventory; an entitled caller can. | Pending source/entitlement policy increment |
| META-011 | Enforce storage/query/evidence bounds and fail closed on required-event persistence failure. | Implemented event/snapshot/export/query bounds; retention/archive and signing rotation pending |
| META-012 | Restart national KMSs and retrieve at the slave while the master is offline, without a new KMS control channel. | `make metadata-demo` |

Retain `make check`, `make demo`, `make relay-demo`, `make segmented-demo` and
affected operational/application checks. `make metadata-demo` exercises the
implemented two-site evidence and incident subset. Use only synthetic material
and labelled synthetic issuer claims.
Incident behavior is specified in [INCIDENT_TRACING](INCIDENT_TRACING.md).
