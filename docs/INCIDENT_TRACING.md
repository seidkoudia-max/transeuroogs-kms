# Incident tracing

Status: read-only local and offline cross-node tracing implemented, 2026-09-12.
The runtime supports node/issuer subjects, material exposure and issuer compromise,
unchanged namespaced keys, and KMS delivery commitments. Provider batch claims,
application/session assertions, online federation, incident holds and automated
remediation remain pending. See [METADATA_RUNTIME](METADATA_RUNTIME.md) for the
exact query, evidence and coverage contract. The remaining design below guides
later increments; it is not a claim that every item is executable today.

## Investigation contract

An authorised query identifies an incident, subject (node/service/issuer/batch),
incident kind, inclusive start/exclusive end in UTC, clock uncertainty, domain
scope and as-of time. It asks which keys and application deliveries may be
affected and why. Investigation is read-only and does not authorise remediation
or sending messages to another organisation.

Each national KMS answers from retained local history and verified evidence.
SES remains a black box: opaque batch references or authenticated impact
summaries can connect service events to local keys. Missing provider evidence
is a coverage gap. No new inter-country KMS control link is required.

## Historical model

Index namespaced keys to events, subjects to events, predecessor events to
dependants and delivery commitments to opaque application/session references.
Relations must come from validated bindings, not arbitrary caller assertions.

Represent custody as an interval from material acceptance/storage to explicit
local clearing. Forwarding alone does not prove clearing. An absent end event
leaves exposure open or uncertain. A key generated before the incident can be
affected if still held during it; a later delivery can depend on earlier exposure.
Searching only creation timestamps would miss both cases.

Runtime `holding_material` and `material_cleared` describe committed repository
snapshots. They do not prove physical erasure from Go heap copies, TLS buffers,
backups or a compromised host. Ingestion that receives and burns bytes between
snapshots is marked possible using request/commit bounds. Missing subject history
or a missing namespace/pair/key binding in upstream evidence stays unknown.

The current relay forwards unchanged keys. Future transformations need reviewed
input/output event semantics. Distinct keys on separate paths do not become
descendants of each other merely because routing used multipath.

## Evaluation and disclosure

1. Authenticate the investigator and authorise subject/domain scope before any
   lookup. Freeze a query watermark and bound the time range and total work.
2. Conservatively intersect custody/operation intervals with the incident window,
   including clock uncertainty. Unknown bounds produce uncertainty, not exclusion.
3. Seed keys/events from local facts and admissible provider claims. Issuer
   compromise affects confidence in claims even without proven material custody.
4. Traverse validated downstream relations, deduplicate namespaced references,
   detect cycles and enforce depth/work bounds. Missing history stays visible.
5. Join per-recipient lifecycle state and application assertions at the watermark.
   A delivery commitment means the KMS burned its right; receipt/business use
   needs a separate authenticated application assertion.
6. Apply audience restrictions and return evidence paths plus coverage. Retain
   a material-free record of who performed the inquiry.

Results distinguish affected under the stated incident assumptions, possibly
affected due to uncertain history/timing, and unknown due to unavailable evidence.
An unaffected conclusion applies only within reported coverage. Include the
reporting domain, as-of watermark, retained time range, unresolved references,
trust exclusions, query limits and provider availability. Bind continuation
tokens to the caller, query and watermark. Limits never imply complete coverage.

Applications see their own deliveries. Controllers receive authorised aggregates.
Only incident roles can inspect permitted event/session details. Exclude material,
material-derived fingerprints and unrelated topology. A signature does not prove
history is complete or truthful when its trusted issuer was compromised.

## Remediation

The following incident-specific command/hold workflow is pending. The runtime's
POST trace endpoint is read-only. Existing local invalidation and 020 void
propagation do not implement these incident action IDs, holds or notifications.

An independently authorised command binds the incident to an exact key set.
Recheck lifecycle state atomically with a hold/invalidation. A committed hold
blocks both new reservations and consumption of existing reservations. Consumed
rights stay consumed. Persist the action and idempotency binding before external
effects; conflicting action-ID reuse fails.

Use durable 020 void propagation only in network mode. In segmented mode,
provider invalidation requires an actual SES capability and authorisation.
Do not turn the application's KID channel into KMS administration traffic.
Report locally invalidated, already delivered, unknown, remote pending or failed
per endpoint. Local completion under partition is not global revocation, and a
local tombstone cannot establish remote erasure. Application notifications use
the separately approved integration/incident workflow.

## Synthetic acceptance exercise

Use the two national KMSs, synthetic provider and authenticated reference app.

| Fixture | Expected finding |
| --- | --- |
| Old key held during the incident | Affected despite earlier generation |
| Key explicitly cleared before the window, with bounded clocks and complete history | Outside that material-exposure interval within reported coverage |
| Key delivered after an affected custody event | Affected downstream commitment; distinguish confirmed usage |
| Distinct key on a separate path with complete history | No inferred dependency on the affected path |
| Missing SES history/batch reference | Unknown provider coverage; no global clearance |
| Missing custody end or uncertain overlapping clock | Possibly affected, with reason |
| Conflicting replay, forged signature or non-authoritative issuer | Rejected without changing accepted history or lifecycle |
| Unknown-ID allocation or lost delivery response | Uncertain attempt/commitment; no invented ID or usage claim |
| Partition, retention gap, inaccessible archive or traversal limit | Explicit partial report |
| Hold racing with reserved-key delivery | Pending incident-hold implementation and acceptance |
| Incident invalidation retried after restart, with an already-consumed peer | Pending incident-command implementation; existing 020 void tests remain separate |
| Unrelated application query | Denied or restricted to its own association summary; controller aggregate adapter pending |

Repeat tracing after restart and compare stable evidence bindings. Inject failures
between lifecycle commitment and event publication. Test historical custody and
delivery relations, rather than validating the query against current state alone.
