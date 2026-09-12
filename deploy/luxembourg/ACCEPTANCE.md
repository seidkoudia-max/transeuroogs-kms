# Luxembourg relay acceptance — 2026-09-12

The local Ubuntu/MicroK8s lab completed all 37 checkpointed acceptance steps for
the synthetic `windhof -> jfk-idq -> jfk-tq -> betzdorf` path. Four endpoint KMSs
and the complete TeraFlow controller were restored and left running. No physical
QKD equipment, real keys or vendor credentials participated.

| Check | Observed result |
| --- | --- |
| First geographic link unavailable | Windhof reported zero ready keys and rejected delivery with 503; source restart preserved that state |
| Second geographic link unavailable | Pending material reached JFK through the co-located ETSI 020 handoff; Windhof still rejected delivery |
| JFK restart during the second outage | Both JFK processes recovered pending relay state; delivery remained blocked until Betzdorf started |
| Full-path acknowledgement | All 64 synthetic KIDs became available at the source after downstream acknowledgement |
| End-to-end delivery | Three two-key tests matched all six 256-bit keys and selected KIDs at Windhof and Betzdorf |
| Local policy through real TFS | Betzdorf pause, evidence-required and resume each advanced its revision once despite exact command retries; other nodes stayed at revision zero |
| Evidence policy | Unknown incoming provenance was rejected when evidence was required, then allowed by the explicit synthetic-lab policy |
| Identity boundaries | Non-controllers denied management; controller denied key APIs; JFK denied local SAE access; wrong peer and SAE/controller identities denied the JFK 020 endpoint |
| Source outage | Betzdorf delivered the selected keys while Windhof was stopped |
| Replay and restart | Repeat delivery rejected before and after all four endpoint processes restarted |
| Complete controller outage | All seven TFS Deployments scaled to zero, their pods removed, and matching application delivery still succeeded |
| Metadata history | Fixed-watermark pagination found the same 64 KIDs at every node; both JFK relays reported no held material after acknowledgement; control events matched revisions |
| Inventory restoration | Real NBI reads and admin-topology membership verified all four synthetic device records after controller restart |
| WebUI | Admin context/topology showed five enabled devices: the four labelled synthetic endpoints plus the existing LU-KMS |
| Repeat-run guard | Invoking a completed runner returned without reseeding, repeating delivery or restarting services |
| Repository regression | `make check` passed formatting, vet, race tests and build; `make demo` verified 1,000 matching unique synthetic keys, depletion, mTLS and replay rejection |
| Deployment tests | Seven Luxembourg tests and six base-lab tests passed; checkpoint ambiguity, concurrent runner exclusion, endpoint identity, role and volume isolation covered |

At completion, Windhof and Betzdorf each reported 58 eligible remaining keys and
six delivery commitments. Both JFK endpoints reported zero available keys,
zero delivery commitments and no pending transfers. Policy revisions were
`windhof=0`, `jfk-idq=0`, `jfk-tq=0`, `betzdorf=3`.

The existing native arm64 KMS image and pinned TeraFlow v7 controller images were
reused from [the base image inventory](../teraflow/observed-images.json). The KMS
runtime source is `5e8e172421c11b23407a355ca4ea8ff5188cc64a`; this increment changes
test-PKI generation, deployment profiles and acceptance code, not key lifecycle
or wire protocols. The new test-PKI binary was cross-compiled from this increment.

The runner log and checkpoint remain inside the VM at
`/opt/transeuroogs/logs/luxembourg-acceptance.log` and
`/opt/transeuroogs/lux-lab-state/acceptance.json`. The initial client import-path
error was corrected before any application delivery, and the run resumed using
the preserved journals. The UI check exposed an upstream custom-topology lookup
limitation; the final profile uses verified membership in the existing admin
topology. No controller source patch or key-state reset was needed.

These are process-stop and restart tests, not packet-loss, uncertain-send, HA,
throughput or conformance certification. History checks compare lifecycle
records and control-event counts; cryptographic evidence verification is covered
by the existing metadata unit/demo suite, not independently certified here.
Only the configured Windhof-master/Betzdorf-slave direction was tested.

ETSI 020 runs only between the two logical KMS domains at the shared JFK site.
Geographic transport is the synthetic TLS relay. QKD link-key ingestion and
consumption, integration of upstream 014 with inter-KMS mode, approved hardware
profiles and physical IDQ/QUKY acceptance remain pending. The one-hour key TTL
and freshness limit intentionally make this batch expire without replenishment.
See [the runbook](README.md) for recovery and the next hardware increment.
