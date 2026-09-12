# Local TeraFlow allocation acceptance — 2026-09-12

This records a real, single-node controller deployment on the development Mac.
All key material and credentials were synthetic. The source/digest inventory is
in [observed-images.json](observed-images.json); these locally built images have
not been published to an external registry. The KMS Go source is the SDN
increment; this deployment increment changes lab scripts, packaging and docs.

## Verified checks

| Check | Observed result |
| --- | --- |
| Upstream controller | Context, Device, Service, PathComp frontend/backend, QKD App, NBI and WebUI running under MicroK8s |
| Device onboarding | Real Device gRPC and HTTP NBI discover the LU KMS node and configured application |
| UI | HTTP 200; LU-KMS appears after choosing Context(admin):Topology(admin) |
| Policy actuation | Pause/resume through HTTP NBI and Device; exact retries advance the KMS revision once |
| Local enforcement | Paused retrieval returns 503; resumed applications receive matching pairs |
| Single use | A second slave delivery of the same selected IDs is rejected |
| Identity isolation | Applications/investigator cannot use management; controller cannot retrieve keys or investigator history; wrong server URI rejected |
| Namespace isolation | A pod in an unrelated namespace cannot connect to the KMS; authorized mTLS clients remain functional |
| Lost reply | Fault injected after a real NBI policy commit; the original command remains in a private durable outbox |
| Pod restart recovery | KMS, Context, Device and policy-client restarts preserve pause, onboarding and pending command identity; replay does not duplicate the revision |
| Complete VM restart | Database and its certificates, KMS state, Kafka data and pending policy survive stop/start; revision 4 remained revision 4 after replay |
| Complete controller outage | All seven TFS Deployments scaled to zero and their pods removed; paired single-use retrieval still succeeds under the last local policy |
| Restoration | All controller services restored; NBI retrieves the persisted device |
| Policy history | Investigator pagination covers the fixed history watermark; one control event per committed revision |
| Repository checks | `make check`: formatting, vet, race tests and build; `make demo`: 1,000 matching unique keys, depletion, mTLS and replay rejection |
| Deployment checks | Six automated namespace/password/image-selection checks; Python and shell syntax; Lima template validation |

The repeatable runner is [run-acceptance.sh](run-acceptance.sh). Its controlled
end-to-end run exited successfully with revision **10**, delivery resumed and
all controller services restored. Its
reply-loss injection occurs in the caller **after** a genuine controller request
returns. This tests recovery from an uncertain outcome; it is not a network
chaos or HA benchmark. History checks inspect signed-page structure and event
counts; the existing metadata unit/demo suite covers signature verification and
tampering. This run does not independently certify cryptography or standards.

## Restart defects resolved during deployment

Docker's forwarding policy is configured to survive a VM restart so pod traffic
continues to work. CockroachDB bootstrap certificates have a separate persistent
volume; retaining the database while losing container-local certificates no
longer prevents restart. Existing KMS and database contents were preserved.
The non-root KMS retains private 0700 storage and regular 0600 signing files;
Kubernetes Secret projection is adapted using a private memory volume.

Cold boot can take several minutes while DNS, database and Kafka become ready
and dependent controller processes retry. This is single-node recovery, not
zero-downtime controller availability. Only the local WebUI is automatically
forwarded; the NBI remains inside the isolated VM/cluster.

## Remaining milestone boundaries

- Physical QKD topology/telemetry, path provisioning, priority/bandwidth admission
  and a continuously running multi-country policy service.
- Two-domain partial-failure reconciliation and relay/route changes during
  in-flight transfers tested through a deployed controller. Existing local
  repository tests cover those key-lifecycle rules, not this cluster scenario.
- IDQ Clarion KX/Q-KMS profile and Clavis hardware acceptance; SES/EAGLE-1 actual
  interface agreement and partner interoperability.
- Provider provenance attestations and agreed accessible ETSI 021/023 wire
  models; independent assessment of the bounded 015 implementation.
- Production PKI, DB peer identity verification, durable provider replenishment,
  controller HA, backup/restore drills, observability and capacity planning.

The current lab has 24-hour test certificates and synthetic key expiry, with
12-hour allocation freshness limits. It intentionally fails closed after those
limits. Restarting neither creates new keys nor erases consumed-key tombstones.
See [the runbook](README.md) for persistence, renewal and start/stop instructions.
