# SDN service and orchestration increment

Implemented source increment, 2026-09-13. TeraFlow remains the controller. The
KMS enforces local allocation and service state; the reference orchestrator
coordinates material-free commands across independently committing KMSs.
The SES-owned EAGLE-1 middle segment is unchanged.

This is a **partial 015 V2.1.1 profile, without independent conformance evidence**.
The previously deployed TeraFlow/Luxembourg images have not been upgraded by this
increment. New acceptance uses two separate KMS processes and the actual pinned
TeraFlow v7 driver contract, not the full controller cluster or physical devices.

## Coverage and remaining gates

| Gap | Implemented and tested | Remaining evidence or work |
| --- | --- | --- |
| Application lifecycle | Catalog-scoped registration, replacement and removal; durable expiry/delivery gate in all three repositories; reserved material invalidated on removal | Dynamic trust onboarding, multicast/shared-key applications, consumption statistics |
| Physical-link control | Catalog desired-state create/update/delete, revision acknowledgements, separate adapter identity | IDQ/ThinkQuantum/SES control agreements, vendor adapter implementation and hardware acceptance |
| Monitoring | Independent scoped adapter reports, sequence/freshness checks, SKR/ESKR in 015; scoped command pages and TFS sampling | 023 model, standard notification payload/transport, device alarm taxonomy and archival |
| Metadata allocation | Existing source/evidence/issuer/age/batch/route policies composed with service state | Guaranteed bandwidth/jitter, priority/admission scheduling and automatic physical-path computation |
| Multiple domains | Persisted pause → provision → configure → activate workflow, exact retry, partial outcomes, conservative abort | Distributed availability/HA, controller-NBI workflow deployment and multidomain interoperability assessment |
| 021 and 023 | Explicit unavailable-input markers and implementation boundaries | Approved authoritative documents/models and agreed versions; no draft wire implementation claimed |
| 015 transport/schema | Published-model JSON validation, conditional catalog CRUD and existing TTL profile | Full RESTCONF discovery/YANG library, standard event streams, complete model operations and independent assessment |

Sources: [015 V2.1.1](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/015/02.01.01_60/gs_qkd015v020101p.pdf),
[021 work item](https://portal.etsi.org/webapp/WorkProgram/Report_WorkItem.asp?WKI_ID=67987)
(stable draft 0.0.1, 2025-12-02),
[023 work item](https://portal.etsi.org/webapp/WorkProgram/Report_WorkItem.asp?WKI_ID=69537)
(stable draft 0.0.6, 2026-06-08). No approved draft copies were supplied; the
public sources checked did not provide usable authoritative draft models.
Project endpoints are not placed under an invented ETSI 021/023 namespace.

## Local authority and safe lifecycle

Opt in with `sdn.services: {"links": [...]}` in the initial configuration. Omitting
this field preserves the previous always-configured application behavior and
snapshot encoding. With this field present, applications initially have no
registration and cannot deliver, including through evidence-provider preflight.
Do not add this feature to an existing journal or reset that journal to enable
it: the immutable configuration binding deliberately rejects that change.
Use a fresh isolated lab state directory; production state migration remains work.

Each application still has an immutable `app_id`, master/slave association and
remote node in `sdn.applications`. Controllers cannot create identities, change
pool IDs, add trust roots, set provider evidence, or retrieve keys. A registration
has a positive local-storage `ttl` (1–2,678,400 seconds), optional expiration
within 31 days, and optional backing links. Registration without backing links
supports local/final-key-pool delivery; it makes no physical-path assertion.
When links are specified, each must belong to that association, be present and
enabled, and have a fresh matching adapter acknowledgement with an enabled
interface and ACTIVE/PASSIVE link status.

Registration/expiry is rechecked under the repository lock at reservation and
consumption. Removing an application clears/invalidates remaining local material
and retains IDs; relay storage also starts durable void propagation to existing
owners. Already consumed keys cannot be recalled. Re-registering cannot revive
old reservations. Exact deletion replay does not invalidate later registrations'
keys. A service expiry gates delivery, while the keys' own expiry remains
independent. A later explicit service extension can permit still-valid reserved
material unless it was invalidated or otherwise terminal.

A link outage does not discard cached final keys or pause a still-registered
application automatically. The last committed metadata policy continues to
apply without a controller. Delivery pause and physical generation enable are
separate operations. Incident holds and existing key protection checks still
apply independently.

## Adapter catalog and desired state

A link catalog entry has:

- `link_id`, `association`, `local_interface`, `remote_interface`, `remote_node_id`;
- `model`, `technology` (one of the supported published QKD type identities);
- `adapter_identity`, `mode`, and `observation_ttl_seconds` (1–3,600);
- `interface_agreement`, required for mode `adapter`.

Local interface numbers and link IDs are unique in this bounded profile.
`mode` is `synthetic`, `pending`, or `adapter`. A mode label or agreement string
alone is not hardware acceptance. `pending` refuses reports and advertises:

| Input marker | Required input |
| --- | --- |
| DEVICE-M01 | Device control interface agreement; 014 key retrieval does not establish generation-control semantics |
| DEVICE-M02 | Implemented adapter, device endpoint and separately provisioned credentials |
| DEVICE-M03 | Telemetry units, status/acknowledgement semantics, clock bounds and vendor acceptance |
| SDN-021-M01 | Authoritative agreed 021 draft document and YANG/API model |
| SDN-023-M01 | Authoritative agreed 023 draft document and YANG/API model |

For SES-associated entries these are **needed SES inputs**, in addition to the
existing [SES metadata checklist](SES_METADATA_CHECKLIST.md) and pool/evidence
agreement. For terrestrial entries obtain equivalent inputs from IDQ/ThinkQuantum.
No new SES inter-OGS protocol is defined here.

Controller principals need `write: true, services: true`. Adapter principals
need `telemetry: true` and the permitted association; they cannot also have
write, route or service authority. The catalog pins each link to its adapter
URI identity. Both roles remain separate from applications, investigators,
providers, peer KMEs and protection operators.

Desired link mutations increment `desired_revision`; an older report is not an
acknowledgement of a newer request. A report supplies a strictly increasing
`sequence`, exact `desired_revision`, bounded `observed_at`, link/interface
status and optional `skr`, `eskr`, `qber`. Future/stale observations, decreasing
sequences, wrong adapters and pending-mode reports are rejected. ESKR cannot
exceed SKR when both are supplied. Project QBER is a decimal string with three
fractional digits, in percent [0,100]; vendor normalization needs agreement.
Rates are integer bits/second. The synthetic adapter explicitly refuses other
modes. No implementation here calls a real device control API.

Stale or unacknowledged observations are omitted from the 015 operational fields,
while the project view retains the last report with `observation_fresh: false`.
The pinned 015 model uses an unqualified `'PHYS'` string in its physical-performance
`when` condition; validation with correctly qualified JSON identityrefs rejects
`phys_perf`. Therefore QBER remains in project reports; 015 exposes SKR/ESKR.
The upstream files and their checksums are unchanged. Resolution of that
model/validator condition requires an agreed profile, not a local model patch.

## HTTP and TeraFlow profile

`POST /management/v1/commands` now accepts one exclusive `service` change:

```json
{
  "command_id": "15a2c94f-4b61-41e7-b2c6-36c91d6a5184",
  "expected_revision": 12,
  "association": {"master": "SAE-LU", "slave": "SAE-GR"},
  "service": {
    "operation": "application_create",
    "resource_id": "a987382b-f787-4012-943e-6874c7769335",
    "ttl": 600,
    "backing_links": ["2e9da08a-01de-4c86-94eb-2114929bddcb"]
  }
}
```

Operations are `application_create/update/delete`, `link_create/update/delete`
and `link_report`. Application create/update replaces optional expiration and
backing links. Link create/update requires `enabled`; link report requires
`report`; deletions accept only operation and resource ID. Link deletion is
refused while a registered application references it. These commands cannot
be combined with rule/route/TTL deltas. Unknown or duplicate members are rejected.

The conditional 015 profile adds:

| Method | Path under `/restconf/data/etsi-qkd-sdn-node:qkd_node` | Payload |
| --- | --- | --- |
| POST | `/qkd_applications` | `etsi-qkd-sdn-node:qkd_app`: one-element list with the locally configured identity/node fields, CLIENT type, supported QoS, optional expiry/backing links |
| PUT / DELETE | `/qkd_applications/qkd_app=<UUID>` | Full supported application replacement / empty body |
| POST | `/qkd_links` | `etsi-qkd-sdn-node:qkd_link`: one-element list containing `qkdl_id` and `qkdl_enable` |
| PUT / DELETE | `/qkd_links/qkd_link=<UUID>` | Same desired link fields / empty body |

All mutations require a stable `X-Command-ID` and `If-Match: "<revision>"`.
Creates return 201, replacements/deletes 204; exact retries retain the original
result. Unsupported QoS properties are rejected. Desired link CRUD acknowledges
a durable request, not physical completion. Project state exposes the adapter
acknowledgement separately. `GET` supports configured interfaces and present
links as well as registered applications and their existing QoS/TTL resources.

`GET /management/v1/changes` requires `X-After-Revision: <integer>` and returns
up to four scoped commits, `next_revision`, and the observed node `revision`.
Persist `next_revision` after processing and fetch until caught up. Revisions may
skip commands outside the caller's scope. These are committed management changes,
not all key lifecycle/incident events and not automatic timer-expiry events.
Investigator access is still required for signed key history. Pages use the
existing bounded/audited HTTP response path; they are not standard SSE streams.

The TeraFlow driver discovers `/interface[...]` and `/link[...]` inventory.
`SubscribeState`/`UnsubscribeState` accept `__transeuroogs_state__` and
`__transeuroogs_changes__`, duration/interval seconds (1 ≤ interval ≤ duration ≤
86,400). `GetState` polls on the subscribed schedule, supports termination and
permits one consumer per driver. Transport failures produce error samples and do
not advance the event cursor. There is no background sample archive; the driver
cursor is session-local, while external consumers can persist the API cursor.
No full TFS monitoring/NBI integration is established by the contract test.

## Multi-domain workflow

`Orchestrator(drivers, journal).run(desired)` accepts 2–16 locally supplied TFS
drivers and an explicit target per domain: `node_id`, immutable observed `pool`
(or `{}` for an unbound local lab), `association`, complete `rule`, optional
configured `routes`, and optional application create/update `service` command.
Each domain can have a different pool ID. This is management coordination,
not pool/KID synchronization or a key-sharing channel.

It observes all participants before acting, persists all command IDs/revisions,
pauses participants, provisions requested applications, applies desired policy
while paused, then activates. A private single-writer journal uses a process
lock, atomic replacement and file/directory fsync. It survives orchestrator
restart and does not discard uncertain commands. Every action uses a node-wide
revision: concurrent telemetry or operator changes can cause a conflict, which
is reported instead of silently rebasing or overwriting that change.

There is **no distributed atomic commit**. During initial pause some domains may
still serve, and during activation some may already serve before another fails.
`incomplete` / `partial_activation` retains progress and exact pending intent.
`run` with the same desired input replays that intent. A different input cannot
replace it. The status describes command outcomes, not a continuous availability
guarantee. Deployments need agreed controller ownership of the managed service.

`abort()` independently pauses every reachable participant using its currently
observed rule. It preserves later restrictions, routes, incident holds, key
ownership and tombstones; it does not restore old policy or undo consumed keys.
Unreachable/conflicting nodes leave status `aborting`, with per-domain progress
and stable pause commands for retry. A concurrent change that defeats a pending
pause's CAS requires operator reconciliation; no automatic overwrite is attempted.
An aborted journal cannot resume activation. Retain journals as evidence and use
a new journal for a separately approved new workflow. Lifetime archival, automatic
rollback/replanning and HA coordination are not implemented.

## Acceptance

```sh
make check demo
make sdn-demo
make sdn-services-demo
.local/sdn-venv/bin/python tests/validate_sdn_yang.py .local/sdn-node.json
.local/sdn-venv/bin/python tests/validate_sdn_yang.py .local/sdn-services-node.json
```

The new demo uses separate temporary trust roots, synthetic keys and two KMS
processes. It checks blocked unregistered delivery, separate adapter authority,
unacknowledged desired state, TFS inventory/sampling, multi-domain application
provisioning, lost activation response, both KMS restarts without reseeding,
exact replay, per-node local key-pair delivery and abort preserving a newer
restriction. It does not test cross-domain key matching, hardware or full TFS
cluster provisioning. Existing relay/segmented labs cover their separate key
planes. Unit/race tests additionally cover deletion invalidation in all three
repositories, void propagation, scope, expiry, stale/future reports, duplicate
requests, storage failure, binding changes, partial abort and single-writer locks.
