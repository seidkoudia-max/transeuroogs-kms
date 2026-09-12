# OGS domain pools and provider pairing

Status: design proposal following the project owner's 2026-09-12 clarification.
Explicit pool identifiers and pool mapping are **not implemented**. This document
does not change deployed configuration, key delivery APIs or the SES contract.

Each OGS domain needs a dedicated administrative pool namespace. Within that
namespace, allocatable final-key pools must identify the remote OGS/service and
permitted use. An OGS that serves several QCI domains cannot treat all received
keys as interchangeable: an LU–GR key cannot satisfy an LU–DE request. One KMS
may eventually manage multiple pools without collapsing their authorization,
provenance or lifecycle boundaries. Start with one configured pair per pool.

## Identity model

The following names describe project data, not published SES or ETSI fields.

| Reference | Meaning and authority |
| --- | --- |
| `domain_id`, `ogs_id` | Local QCI/OGS ownership, provisioned by the site operator; several OGSs may belong to one national domain |
| `pool_id` | Stable local final-key pool reference, qualified by domain/OGS; never a bearer credential |
| Provider service binding | Authenticated provider identity, endpoint/gateway pair and final-key service context; an explicit provider pool/service ID is included only if its interface defines one |
| Remote pool binding | Corresponding remote OGS/domain and pool, obtained through an agreed authenticated provisioning/provider mechanism |
| Binding revision | Local immutable version of those mappings; prevents reinterpreting old keys after a mapping change |
| `key_ID` | Individual provider-issued key identifier, preserved unchanged |
| Ordered SAE association | Applications entitled to consume corresponding copies, with master/slave retrieval roles |

For example, two different local names can refer to corresponding inventories:

| Side | Local pool | Provider relationship | Application key |
| --- | --- | --- | --- |
| QCI-LU / OGS-LU-1 | `LU/OGS-1/to-GR/final` | Agreed LU–GR final-key service | Same unchanged KID |
| QCI-GR / OGS-GR-1 | `GR/OGS-1/to-LU/final` | Same agreed service | Same unchanged KID |

The example names are illustrative. A common provider-level pool ID could also
represent this relationship, if SES defines one. Identical local pool names are
neither necessary nor proof that keys correspond. Raw OGS–satellite link material
must remain inside the provider segment; a receiver's raw accumulation pool is
not automatically an application-ready inter-OGS final-key pool.

## Responsibility and synchronization

Retain the three agreed segments: QCI1–OGS1, EAGLE-1, OGS2–QCI2. EAGLE-1 owns
OGS authentication, offline relay and corresponding final keys/KIDs under the
project's provider contract. Add pool/service correspondence to the interface
questions; do not implement a new satellite protocol or a parallel inter-country
KMS synchronization channel by assumption.

SES may scope final inventory through registered gateway SAE pairs rather than
an explicit pool-ID field. A reviewed adapter must resolve the actual mechanism.
For development, an operator-provisioned synthetic mapping can exercise our
local behavior, clearly labelled as configured rather than SES-confirmed.
No authenticated mapping means no claim of confirmed provider pool synchronization.

Pool mapping is distinct from per-key readiness and application consumption.
Only the provider's final-key release permits collection. Local journals enforce
single delivery independently: one application may collect its copy before the
other, so inventory counters need not be equal. A stale remote count must never
restore a consumed, expired or uncertain local key. Application KID notification
and authentication remain necessary; carry the agreed service/pool context with
the selected KID when multiple mappings are supported.

Master/slave remains a role for each service/application association. It does
not designate one permanently authoritative OGS or national KMS for all pools.

## Requests and allocation

The intended selection chain is:

```text
authenticated application + authorized peer/service
    -> authorized pool binding and its revision
    -> eligible final key, atomically reserved
    -> immutable pool/service/KID/association delivery record
```

Keep the [ETSI 014 V1.1.1](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf)
application interface SAE-based: master retrieval selects the peer SAE; slave
retrieval supplies selected KIDs. Its baseline methods do not define a pool-ID
selector or a cross-domain pool synchronization protocol. Resolve pools behind
the API using a configured service association. Never substitute a pool ID for
the SAE path parameter. If clients later need an explicit selector, specify a
versioned project interface or agreed mandatory extension before implementing
it; an unknown or ambiguous pool selection must fail, not silently fall back.

For the first increment, bind each downstream SAE pair to one pool. Reusing one
upstream gateway pair across unrelated applications remains unsupported until
the two sides have a durable, authenticated assignment mechanism. Independently
allocating the next key to different applications at each end is unsafe.

Persist pool bindings with reservations, import intents, keys, consumption,
uncertainty and tombstones. A by-ID request must resolve the original binding;
it must not search other pools after a failure. Mapping changes apply only to
new work, with old records pinned to their existing revision. Unknown outcomes
remain uncertain and are not retried in another pool. Preserve the repository's
existing duplicate-KID rejection; adding namespaces does not authorize KID reuse
or renaming. A future change to uniqueness scope needs explicit migration and
compatibility analysis.

TeraFlow may manage allowed pool bindings and view scoped aggregate inventory,
provenance, freshness, capacity and mapping status. It receives no key bytes and
does not assert provider synchronization. Local KMS enforcement must continue
when the controller is unavailable. Dynamic pool assignment and 015/021/023
representation require their own reviewed profile; no standard field is assumed.

## Implementation increments and acceptance

| Increment | Deliverable and meaningful tests | Current status |
| --- | --- | --- |
| P1 | Typed pool registry, owner/service/peer binding, one SAE pair per pool, persisted revision; reject unauthorized, ambiguous and conflicting mappings | Planned |
| P2 | Allocation and ingestion carry immutable pool context through the repository; cross-pool isolation, concurrent reservations, restart, replay, lost replies and mapping changes cannot cause reuse | Planned |
| P3 | Three-segment synthetic provider models at least two remote OGS pools; verify unchanged KIDs, delayed readiness, wrong-pool requests and independent local consumption | Planned |
| P4 | Pool-scoped metadata and TeraFlow policies; restricted views, signed mapping history and controller-outage enforcement | Planned |
| P5 | Actual SES pool/service mapping adapter and joint acceptance with authenticated deployment inputs | Requires SES interface agreement and access |

The present `core.Key` has KID and an ordered association, but no pool field.
`upstream.Config` specifies one gateway pair and `ingest.Repository` binds that
profile and one local pair to its durable journal. Metadata namespace identifies
evidence scope; it is not an enforced key-pool selector. Thus the existing
single-pair demos provide lifecycle foundations but do not pass P1–P5.

This work complements, rather than completes, the separate integration of
upstream 014 ingestion with terrestrial relay mode and QKD link-key consumption.
The Luxembourg two-link lab does not contain an EAGLE-1 pool synchronization
service. See [EAGLE1_INTEGRATION](EAGLE1_INTEGRATION.md) and the
[SES interface questions](SES_METADATA_CHECKLIST.md).
