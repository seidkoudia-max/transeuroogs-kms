# Remote QCI protection increment

Implemented on `codex/remote-qci-protection`, following the project owner's
2026-09-12 authorization. All acceptance uses synthetic material. The running
TeraFlow/Luxembourg VM retains its previous validated images and journals.

## Implemented software

| Upgrade | Runtime behavior and boundary |
| --- | --- |
| OGS pools | A registry binds local/remote OGS, domain, pool, ordered application pair, provider gateway pair, service, service epoch, purpose and immutable local revision. Local pool names/revisions may differ. One application association per pool; ambiguous/shared gateway assignments are rejected. Local and relay repositories can host multiple pools; segmented intake still has one upstream pool per process. |
| Lifecycle binding | Keys, reservations and upstream intents retain their pool context through delivery, uncertainty, invalidation, tombstones and restart. A mapping/configuration change cannot reinterpret an established journal. No KID rewriting, cross-pool fallback or tombstone deletion. |
| Provider input contract | `synthetic`, `ses-pending` and `ses-reviewed` modes, explicit missing-input records, bounded retention/age/clock parameters and agreement references. `ses-pending` blocks allocation. Reviewed activation requires the implemented 014 profile and evidence contract, not simply changing a Boolean. |
| Provider evidence | Strict RFC 7515 JWS / RFC 7518 ES256 verification through go-jose; pinned public JWK, issuer/service scope, credential validity/revocation, KID, local mapping revision, service epoch, application/gateway pair, final-key readiness and expiry. Unknown or contradictory evidence cannot satisfy policy. |
| SES adapter boundary | A bounded 014 client plus a local signed-evidence directory interface. The normalized evidence schema is a **project adapter contract**, not a published SES payload. SES must supply/agree the actual metadata interface and delegated signing authority or an adapter translating it. |
| Local incident remediation | Scoped mTLS operator actions (`hold`, `invalidate`, `release`), durable action/incident IDs, optimistic revision checks and exact-replay handling. Holds block new allocation and consumption of existing reservations. Release never restores invalidated material. Controllers and applications cannot issue operator actions. |
| Remote remediation | Terrestrial invalidation starts existing asynchronous 020 void propagation. Results distinguish local invalidations, already-delivered copies and remote work pending. Segmented SES invalidation reports `provider_action_needed`; no unagreed SES revocation method is called. An issued result is the observation at that action, not proof of later global completion. |
| Uncertain outcomes | Operator-visible immutable request references; optional non-consuming provider status query, durable query intent/result and exact replay. Baseline 014 reports `unsupported_by_provider`. Even `not_consumed` never revives/retries a burned request. |
| Application binding | Version 2 reference notifications bind both local pool names, common service/epoch and purpose inside authenticated notification and TLS 1.3 PSK confirmation. Each local ledger also pins its local revision. Version 1 remains available only for configurations without a pool. No downgrade on a pool-bound association. |
| Usage/retirement receipts | Scoped application reports require prior delivery to that authenticated SAE. Session/KID assignments cannot change. The reference application has a durable receipt outbox and checks current pool holds before invoking its callback. Retirement is an application's report, not proof of a commercial encryptor's secure erasure. |
| Metadata and SDN | Pool mappings, operator actions, receipts and reconciliation observations share the signed lifecycle snapshot commit. Verified evidence is included in scoped history and used by existing source/freshness/evidence policies. Management views expose pool bindings and local protection gates. Controllers receive no key bytes and cannot assert provider evidence or release incident holds. |
| Protected terrestrial relay | Optional `qkd-jwe-v1` peer mode consumes a **separate** 256-bit 014 link key per application-key transfer; protects it using standard JWE `dir`/`A256GCM`; pins ciphertext/peer across retries; journals uncertain allocation, retrieval and engine handoff. The three-node test models Windhof–JFK and JFK–Betzdorf as two independent link pools. |
| HSM integration | Optional `pkcs11` build uses pre-provisioned, locally generated, sensitive, non-exportable AES-256 token objects for PostgreSQL snapshot wrapping. PINs are read from private files. No fallback to a file key when HSM configuration is selected. SoftHSM tests cover sealing, recovery across wrapping-key rotation and AAD rejection. No real HSM certification/acceptance is claimed. |
| Independent checkpoint witness | Optional mTLS authority stores monotonically advancing ciphertext digests/versions. PostgreSQL advances it before local checkpoint/DB commit; uncertainty poisons the writer. Startup refuses a mismatching witness or disabling a previously required witness. A reference server and real PostgreSQL combined-rollback test are included. This does not provide automatic HA or protect a witness restored with the same old backup. |

## Provider agreement inputs

No invented SES values are substituted. The registry's `needed_SES_input` list
contains stable identifiers and `owner: SES`. Numeric unknowns are represented
by missing/null values in the contract, not zero or guessed durations.

| ID | Required input |
| --- | --- |
| SES-I01 | Reviewed interface-agreement reference |
| SES-I02 | Actual API/key-identifier/size profile; implemented bounded adapter: `etsi014-final-uuidv4-256-v1` |
| SES-M17 | Final-pool selection: current adapter supports `gateway-pair`; explicit provider pool selectors need the actual interface definition |
| SES-M18 | Corresponding service/epoch/mapping and final release semantics; current reviewed profile requires `paired-final-keys-only` |
| SES-I05 | Retention duration |
| SES-I06 | Maximum final-key age/validity |
| SES-I07 | Provider timestamp uncertainty bound |
| SES-I08 | Non-consuming recovery capability and semantics; explicitly `unsupported` is valid when the provider offers none |
| SES-I09 | Evidence source, format and authorized signing/delegation profile |
| SES-I10 | Gateway/OGS authentication and trust agreement |

Endpoint addresses, gateway identities, credentials and the local-to-provider
mapping also require authenticated provisioning. The SES-M19 shared-pool
application-assignment question remains open: independent applications cannot
share a consuming gateway pair in this profile. No new national KMS-to-KMS
synchronization channel is assumed. EAGLE-1 still owns its satellite segment.

The [pending configuration example](../deploy/config/federation-pending.json)
is a local synthetic configuration with allocation disabled; its names are
illustrative and are not SES-issued identities. It can be inspected with the
normal configuration validator and `/federation/v1/state`. Supply test PKI to
run it. Do not convert it to `ses-reviewed` without resolving the actual contract.

## Project APIs

All use the KMS mTLS listener. JSON is bounded; secret material is absent from
these request/response schemas. Pool selection in baseline 014 remains the
configured ordered SAE association, not a substituted URL pool parameter.

| Endpoint | Authorization and effect |
| --- | --- |
| `GET /federation/v1/state` | Scoped operators/apps: configured pools, unresolved SES inputs, local holds, receipts and operator reconciliation results |
| `POST /federation/v1/actions` | Operator with `operate: true`: action/incident UUIDs, pool, expected revision, operation and bounded reason |
| `POST /federation/v1/evidence` | Scoped operator: pool and JWS; proof must independently pass configured signature/scope validation |
| `POST /federation/v1/receipts` | Authenticated local SAE: receipt/session/KID, full pool binding, ordered association and reported status |
| `POST /federation/v1/uncertain` | Scoped operator: pool; returns public uncertain-request references, counts and known IDs |
| `POST /federation/v1/reconcile` | Scoped operator: pool, action UUID and request reference; query only, never collection or restoration |

An incident action example (use fresh UUIDs for a new action/incident):

```json
{
  "action_id": "2d23a3bc-38cb-422c-904f-dcd42e5067cd",
  "incident_id": "6f4c5399-d776-42ef-bc8c-25bbb057d9c4",
  "pool_id": "LU/OGS/to-GR/final",
  "expected_revision": 0,
  "operation": "hold",
  "reason": "synthetic incident exercise"
}
```

Each pool's entire immutable context is stored in `federation.pools[].binding`.
`service_epoch` is common correspondence context. `binding_revision` is local;
different values at the two OGSs are legitimate when the provisioned mapping
agrees. Service/epoch/purpose changes require a separately reviewed migration;
editing configuration in place fails startup.

The relay uses an explicitly project-defined mandatory context extension
`E0_transeuroogs_pool_v1` when a pool is configured. Both peers must support it;
missing/unknown/different service context is rejected. This extension is not an
ETSI-assigned identifier or a conformance claim.

## Terrestrial protected transport

`inter_kms.peers.<peer>.mode = "qkd-jwe-v1"` enables the project endpoint
`/qkd/v1/ext_keys`. A bare plaintext 020 transfer is not accepted there. ACK/void
control messages still use authenticated TLS. Configure a dedicated
`inter_kms.qkd_state_dir` and each peer's `link_key_source` using the ordinary
upstream TLS/014 configuration. A source has role `master`; the paired incoming
peer has role `slave`. Hardware uses `etsi014-link-uuidv4-256-v1` with an explicit
interface-agreement reference; synthetic tests use `synthetic-segmented-v1`.

The JWE is standard authenticated encryption, **not** an OTP or an
information-theoretic authentication claim. The trusted JFK process sees the
application key, decrypts under one link key and re-encrypts under the other.
The transport supports one application key per envelope, as the relay worker
sends one per intent. It never divides a key into shares. Source expiry is
propagated through the path and cannot be extended by the receiving nodes.

A lost consuming reply remains uncertain. Restart retries only cached sealed
ciphertext or a durably decrypted engine handoff, never a link-key retrieval.
Link and application IDs remain separate; application KIDs are preserved.
The protected-transport journal is encrypted local state, separate from the
PostgreSQL lifecycle snapshot. Its deployment/backup protection must be included
in a site's custody/recovery acceptance; this increment does not automatically
put that journal behind the PostgreSQL HSM/witness backend.

Top-level segmented final-key delivery and inter-KMS lifecycle mode remain
separate. The new **per-peer** 014 link intake composes with terrestrial relay;
it does not blindly inject SES final keys into a second satellite-relay protocol.

## HSM and witness operation

Build with `go build -tags pkcs11` and CGO enabled for an HSM deployment. The
normal static image has no PKCS#11 module and fails if HSM custody is requested.
Under `operational.database`, choose either `wrapping_key_dir` or `hsm`:

```json
{
  "hsm": {
    "module": "/absolute/path/to/site-pkcs11-module.so",
    "token_label": "SITE_INPUT_REQUIRED",
    "pin_file": "/private/site/pin",
    "active_key_id": "v2",
    "key_labels": {"v1": "previous-wrapping-key", "v2": "active-wrapping-key"}
  }
}
```

Keys are provisioned by the HSM administrator. Keep old wrapping objects until
all retained snapshots/backups no longer depend on them. A distinct label/ID is
required for each generation. Follow the device's AES-GCM limits and rotate
before exhausting its per-key usage bounds. SoftHSM demonstrates integration;
it provides no physical HSM protection.

`operational.database.witness` references an HTTPS endpoint, expected URI SAN,
CA/certificate/key files and CRLs. `kms-witness --config <file> --initialize`
explicitly creates a new authority store; later starts omit `--initialize`.
The server configuration contains `state_dir`, `listen`, TLS file references,
`crl_files` and `grants` mapping KMS certificate URI identities to namespaces.
Run the real witness under independent administration and retention. Missing
or ahead-of-database witness state blocks startup. An uncertain write may require
operator recovery; it must not be "fixed" by resetting the witness.

## Acceptance and remaining boundaries

Run `make check`, `make demo`, `make federation-demo`, `make relay-demo`,
`make metadata-demo`, `make sdn-demo`, `make app-test` and
`make operational-demo`. HSM acceptance additionally runs:

```sh
KMS_TEST_PKCS11_MODULE=/absolute/path/to/libsofthsm2.so \
  go test -race -tags pkcs11 ./src/internal/wrapping
```

Meaningful new cases cover pool ambiguity/isolation, wrong service/epoch,
concurrent incident/consumption, failed commits, restart, two corresponding
remote services, evidence tampering/expiry, reconciliation without retries,
application context downgrade, signed protection history, one link key per hop,
lost handoffs, ciphertext tampering, HSM rotation and witness CAS/rollback.

Local acceptance completed on 2026-09-12: `make check` (format/vet/race/build),
the 1,000-key demo, the 64-key federation/metadata demos, direct/multipath/failover
relay, the TeraFlow driver contract demo, ten application tests, SoftHSM wrapping,
and real PostgreSQL recovery/application acceptance all passed. The operational
demo confirms two sessions with different local pool revisions and durable
confirmation/retirement receipts. Additional protected-transport and witness
tests use actual mTLS sockets. This record refers to the source branch, not a
deployment upgrade of the running VM.

Still separate work, not marked implemented by these tests:

- Actual SES wire integration/acceptance, SES remote incident/receipt capabilities
  and a shared-provider-pool assignment contract.
- Physical IDQ Clarion KX/Q-KMS and ThinkQuantum QUKY acceptance, actual site CA
  relationships/renewal/revocation, HSM policy, independent witness deployment,
  and tested infrastructure failover. No automatic KMS HA is introduced.
- Unbounded continuous-operation storage: lifetime key/tombstone/history limits
  remain. There is no online tombstone GC, archive-backed state migration or
  metadata signing-key rollover. Do not reset a namespace to evade capacity.
- Integration with the selected commercial encryptor/VPN. Receipts and the
  reference TLS application are software foundations, not vendor acceptance.
- An agreed post-quantum authentication/signature profile. Current signed
  provider/local evidence remains ES256. Go's available algorithms alone do not
  establish an end-to-end PQ-authenticated deployment.
- Full ETSI 015/020/021/023 conformance. Project extensions and synthetic profiles
  retain their explicit status; physical controller service provisioning and
  the previously pending 021/023 interfaces are not completed by this increment.

References: [JWS](https://www.rfc-editor.org/rfc/rfc7515.html),
[JWA](https://www.rfc-editor.org/rfc/rfc7518.html),
[JWE](https://www.rfc-editor.org/rfc/rfc7516.html),
[PKCS#11 Go wrapper](https://github.com/miekg/pkcs11).
