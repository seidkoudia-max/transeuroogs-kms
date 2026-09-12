# SES metadata interface questions

Status: prepared for interface discussions, 2026-09-12; not sent to SES.
Answers remain outstanding. This checklist assumes no additional SES capability.

## Confirmed responsibilities

Gateway authorisation, trusted-node co-location, SES-owned OGS authentication,
paired KIDs and offline satellite relay are already agreed. Master/slave remains
a per-association retrieval role. These decisions do not need to be reopened.
The [integration document](EAGLE1_INTEGRATION.md) records existing interface
evidence. These questions address the proposed [metadata profile](METADATA_PROFILE.md).

## Interface questions and required outcomes

| ID | Question | Required agreement or evidence |
| --- | --- | --- |
| SES-M01 | What scopes a final KID, and is its gateway-pair binding stable across passes, restarts, failover and expiry? | Namespace, no-reuse contract and collision/replay examples. |
| SES-M02 | What reference binds the two endpoint copies to the same final service key? | Paired reference and authenticated statements, without material disclosure. |
| SES-M03 | Are generation, relay completion, availability and delivery timestamps separately available? | Definitions, UTC/precision/uncertainty and delayed-release examples. |
| SES-M04 | Can SES attest the oldest generation bound of all material contributing across contacts? | Conservative whole-key bound and scope, or an explicit unavailable answer. |
| SES-M05 | Which satellite/session/pass/batch references can be disclosed, or replaced by opaque incident references? | Stable identifiers and permitted audience, without internal topology. |
| SES-M06 | Can metadata be authenticated independently of TLS, or retrieved through an authenticated reference? | Actual signature/container or retrieval contract and synthetic examples. |
| SES-M07 | Who may assert each claim, and how are credentials rotated, revoked and checked historically? | Issuer/claim authority and compromise-time trust rules. |
| SES-M08 | Is the transport an I/F G extension, separate API or another mechanism? | Versioned schema, negotiation, limits, errors and test endpoint. |
| SES-M09 | Can metadata be inspected before consuming a key and after delivery? Are reads repeatable? | Read-only versus consuming semantics, especially after a lost response. |
| SES-M10 | Is there common absolute validity for both copies during delayed retrieval and outages? | Readiness, expiry, retention and boundary-test outcomes. |
| SES-M11 | How are compromised services, affected passes/batches and recalls reported? | Authenticated incident query/notice, affected KIDs, retention and coverage. |
| SES-M12 | Is invalidation supported, who authorises it, and how are delivered/unknown/partitioned copies reported? | Idempotency, authorisation and per-endpoint outcomes. |
| SES-M13 | Which equipment, certification or forwarding-protection statements may consumers rely on? | Exact assurance scope, authoritative issuer and evidence reference. |
| SES-M14 | Is inventory/scarcity/entitlement information available per association or service class? | Units, observation time, scope and admission/consumption semantics. |
| SES-M15 | What may cross national boundaries, and what retention/disclosure conditions apply? | Agreed audience views, export and historical-access policies. |
| SES-M16 | Can the test service exercise delayed relay, stale/missing claims, conflicting IDs, issuer rotation and incidents? | Partner test plan with synthetic fixtures and expected outcomes. |
| SES-M17 | Does each OGS final-key service expose an explicit pool ID, or is pool selection implicit in endpoint and gateway SAE pair? | Identifier owner, scope, registration, selector and authorization contract; distinguish raw link accumulation from final inter-OGS keys. |
| SES-M18 | How does each ground service authenticate the correspondence to its remote pool/service and report changes across offline relay, restart or failover? | Shared reference or endpoint-ID mapping, version/epoch semantics, readiness and synthetic conflict/stale-mapping examples; no new API assumed. |
| SES-M19 | Can one provider pool serve several downstream application pairs, and if so how is the same KID assigned to the same pair at both ends? | Agreed immutable assignment and notification contract; otherwise retain one gateway/application pair per pool. |

These additions support the [OGS pool design](KEY_POOL_DESIGN.md). Pool naming,
final-key pairing and local consumption are separate responsibilities. Remote
inventory equality is not an allocation or replay-safety guarantee.

## Decisions when information is unavailable

Keep missing fields explicitly unknown. Do not use ingestion or final release
time as generation time. Without component coverage, reject mandatory whole-key
freshness. Without provider-authenticated evidence, label local observations
separately; a local signature does not manufacture an SES attestation.

A post-retrieval policy rejection may burn material if metadata cannot be
inspected first. Never assume a consuming retry is safe. Without a remote
invalidation contract, support local quarantine only and report remote status
as unknown. Receiver certification does not certify this KMS.

Prioritise identity/pairing, timing, evidence/incident references, transport and
failure semantics for the initial agreement. Produce a versioned support matrix
with available/unavailable/conditional/unconfirmed entries, issuer authority and
disclosure scope. Deployment credentials and real material stay out of Git.

SES owns provider claims. TransEuroOGS owns local event history, unknown handling
and enforcement. Site operators own national trust/disclosure and incident
authority. Partner acceptance is joint work. This checklist requests neither
satellite internals nor a new inter-country KMS control connection.
