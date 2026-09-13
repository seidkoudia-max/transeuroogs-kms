# TeraFlow integrated service acceptance — 2026-09-13

Executed in the existing local `transeuroogs-tfs` Ubuntu/MicroK8s VM with the
actual TeraFlow v7 controller (`fb8707871eba26806cac7ac373c70b2bb5bd26fc`).
Four KMS endpoints, two independent 014 link providers and all test keys are
synthetic. No IDQ/QUKY equipment or SES receiver was contacted.

The checkpointed 20-step run completed at 09:02 UTC. It verified:

- NBI onboarding of four devices, discovery of their configured interfaces and
  link intent commits through the Device driver.
- A lost final activation reply after Betzdorf committed revision 6, followed
  by exact workflow recovery across KMS, provider, Device and worker restarts.
- Matching end-to-end delivery over the two independently protected geographic
  links and trusted JFK interworking, with preserved application KIDs.
- Controller/key-plane and observer/write isolation.
- An incident hold on previously undelivered recipient keys, persistence across
  target restart, release and successful subsequent delivery.
- Matching delivery and replay rejection while Context, Device, PathComp, QKD
  App, Service, NBI and WebUI all had zero replicas; original counts restored.
- Replay rejection after restart, signed history export, and fresh controller
  state at revision 8 on each KMS before periodic adapter reporting.

Restarting providers while consuming link-key requests were active left nine
of the 64 application transfers unresolved. The existing bridge intentionally
does not repeat such requests. The explicit synthetic recovery procedure
retired those nine transfers through authenticated void operations, preserving
tombstones and checking that no material remained usable. The other 55 keys
were ready at both application endpoints. Three two-key deliveries consumed six
of them during the primary run. No pool was reseeded or uncertain key revived.
This is evidence of safe failure handling with an availability cost, not lossless
recovery or automatic production reconciliation.

The signed metadata export verified against all four locally pinned signing
public keys using `kms-metadata trace`. All four retained histories were complete.
The synthetic custody query yielded 122 scoped findings and correctly reported
`complete_within_supplied_scope=false`, with `upstream_history_unavailable`.
Separate local pool/namespace histories are not automatically equated. An
authoritative cross-pool evidence mapping and SES agreement remain required;
the 122 findings must not be described as 122 distinct application keys.

The final deployable bundle records exact source/binary hashes, Git revision and
image child digests in `release.json` and
`/opt/transeuroogs/services-state/images.json`. Runtime credentials, original
Device template, checkpoints, metadata-only delivery receipts, retirement plan
and signed evidence stay in private VM/PVC storage. Tests used small image
overlays; the previous lab's PVCs and configuration were preserved.

Local validation also passed `make check`, `make demo` (1,000 matching keys),
`make sdn-services-demo`, the deployment safety/recovery tests, and pinned 015
YANG validation. These are project checks, not independent standards assessment.

The [runbook](README.md) explains finite lifetimes, restart/rollback, reference
orchestrator versus native ServiceService ownership, and the remaining physical,
standards and production deployment gates. The test does not establish M6 site
acceptance, guaranteed QoS, full 015/020/021/023 compliance or operational HA.
