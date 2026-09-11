# EAGLE-1 segmented integration

Status: implemented synthetic segmented profile, 2026-09-11. Real SES
interoperability and independent conformance remain unverified.

## Agreed responsibilities and evidence

The project owner authorises the gateway role and confirms that the SES-provided,
SES-certified receiver and terrestrial QCI end node share a trusted environment.
The same TransEuroOGS KMS software is deployed in each participating state.
The user selected three segments, with point-to-point distribution, offline
satellite relay, OGS authentication and OGS key-ID pairing delegated to EAGLE-1:

```text
 QCI1 / our KMS1           SES ground service 1
        |-- local 014/mTLS --|                  Segment 1: our local integration
                            |
                    EAGLE-1 black box          Segment 2: SES responsibility
                            |
 QCI2 / our KMS2           SES ground service 2
        |-- local 014/mTLS --|                  Segment 3: our local integration
```

The ground service includes processing/key delivery; the raw optical receiver
is not itself assumed to be the API server. OGS authentication and paired-key
correctness inside the central segment are the agreed provider contract, not
claims independently verified against SES equipment. Receiver certification
does not certify our KMS. The provider's deployment profile is still unknown.

The [SES release catalogue](https://ses-techcom.com/download-category/eagle-1-documents/)
includes Ground Terminal ICD **EAGLE1-00746-SYS-ICD-TCO v3.0, 2025-10-16**.
Section 3.8, page 11, specifies ETSI 014 at I/F G. Receiver detection messages
are described separately in section 3.9, pages 11–12. The ICD lists a separate
Monitoring & Control ICD as unreleased at that publication date.

The [April 2025 SES Q&A](https://www.ses.com/sites/default/files/2025-05/EAGLE1-01577-GQKD-MOM-TCO_V1.0_EAGLE-1%E2%80%93Questions-and-Answers-20250423.pdf),
Q1 and Q40, describes possible accumulation across multiple passes and service
of one ground station at a time. The emulator represents final-key availability
with a delay; it implements no optical, QKD or satellite cryptographic protocol.

## Roles and key-ID flow

Master/slave are roles for a key association, not permanent hardware roles or
an active/standby pair. Our lab configures LU as master and GR as slave for
one association. Another deployment can configure the opposite direction with
an agreed upstream pair and separate state. Live role switching on an existing
journal is rejected because it would change key ownership.

1. QCI1's authorised local application requests a key from our KMS1.
2. KMS1 acts as the master gateway SAE toward SES service 1, using `enc_keys`.
3. The black-box service supplies a final key and its KID for the configured
   gateway pair. KMS1 durably records the binding and delivers its local copy.
4. The application workflow notifies QCI2 of the selected KID and association.
5. QCI2's authorised local application requests that KID from KMS2. KMS2 acts
   as the slave gateway SAE and uses `dec_keys` at SES service 2.
6. SES supplies the corresponding copy. KMS2 commits local consumption before
   delivering it. KMS1 need not be online for this retrieval.

KIDs are preserved unchanged: upstream KID = local KID at both ends. The profile
accepts UUIDv4 and 256-bit keys; other representations fail explicitly. There is
no ID translation, hashing of key material into an ID, or independent renaming.
One downstream application pair maps to one upstream gateway pair per process;
sharing one gateway pair between unrelated application pairs is not supported.

**Pairing and notification are different.** Eagle-1 owns corresponding keys and
IDs in its service. The consuming application must still identify which key was
selected. [ETSI 014, section 4](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf)
leaves application KID notification outside the API. Our demo harness passes
only the IDs between its application roles in memory. A deployment uses its
application session or an agreed SES notification facility; no such additional
SES endpoint is assumed here. A direct inter-country KMS control connection is
not required by this segmented baseline.

## Authentication and trust

Both local interfaces require mTLS, TLS 1.3 and configured certificate identities.
The client verifies the ground service's hostname, CA chain and exact URI SAN;
the server authenticates the configured local application and ordered pair.
Remote application certificates are excluded from the local delivery role,
even if issued by a locally trusted CA. Upstream credentials and downstream
application/server credentials are provisioned separately.

`make segmented-demo` uses three independent test CAs: QCI-LU, synthetic SES and
QCI-GR. The SES emulator checks gateway certificates and restricts each service
to its own gateway. Its shared synthetic store models the central segment's
already-paired result. It does not demonstrate SES's actual OGS authentication.

This provides segmented authentication under the agreed trusted-node model.
It is not a cryptographic proof of the remote application identity across all
intermediates. Application-to-application authentication and key confirmation
belong to the consuming security protocol. Identical KIDs alone do not prove
identical bytes; the harness checks bytes internally without printing them.

## Implemented lifecycle and limits

- `etsi014.Client` performs bounded POST retrievals and read-only status calls.
  Consuming requests are never automatically retried or redirected.
- `ingest.Repository` implements `core.Repository` with a separate encrypted
  journal per national endpoint. Provider profile, gateway pair, local pair and
  capacity are bound to that journal. No terrestrial relay runs during ingestion.
- Requests commit before upstream consumption, and local consumption commits
  before response serialization. Each recipient receives its copy once.
- Interrupted pending requests become uncertain on recovery. A failed slave
  retrieval quarantines the entire requested ID batch, including an explicit
  upstream error: this conservative profile does not assume safe retry semantics.
- A failed master request may have unknown IDs. Its attempt remains recorded;
  correctness relies on the provider never reissuing consumed material. A later
  new allocation is a new request, not recovery of the previous one.
- Master reservations survive restart without returning to available inventory.
  Expiry clears retained material; consumed/invalid/expired IDs remain terminal.
- Lifetime capacity includes attempted key slots, including uncertain requests.
  There is no garbage collection, automatic retry of quarantined IDs, HA or
  anti-rollback guarantee. Requests are serialised per process with bounded
  upstream timeouts. Full snapshots are intended for this lab's scale.
- Local retention starts at collection intent. Upstream retention remains the
  provider's responsibility; there is no claim of common absolute expiry or
  global revocation. Inventory is best effort; an upstream status failure is
  represented as zero available by the current repository contract.

The encrypted journal uses Go's AES-GCM implementation and local wrapping keys,
with the same laboratory host-compromise limitations as the 020 relay journal.
No real key material, credentials or certificates may be committed or logged.

## Configuration and deployment inputs

The only accepted upstream profile is `synthetic-segmented-v1`. The configuration
is generated by [the demo](../emulator/eagle1-kms/demo.py), which shows all required
fields without committing credentials. The KMS `eagle` configuration selects
upstream mode; combining it with `inter_kms` or startup key injection is rejected.

| Configuration | Meaning / real-deployment input |
| --- | --- |
| `url`, `server_identity` | Local ground-service HTTPS address and expected authenticated identity |
| `gateway_identity`, `gateway_master`, `gateway_slave` | Registered gateway certificate identity and upstream SAE pair |
| `role`, top-level `local_saes` and `associations` | This endpoint's master/slave role and authorised local application pair |
| `remote_kme_id` | Configured remote national KMS identity for status metadata |
| `pki_dir`, `certificate_name` | Upstream trust bundle and gateway credentials, separate from the local server's `--pki-dir` |
| `state_dir`, `lifetime_seconds`, top-level `capacity` | Private local journal and explicit retention/capacity policy |

SES/site operators must supply actual endpoint identities, certificate enrolment
and renewal/revocation policy, supported methods, key representation, API limits,
readiness/retention/error semantics, monitoring/control ICD and test access.
These remain integration inputs; gateway authorisation is already settled.
Real-service enablement requires a reviewed deployment profile and partner tests.

## Verification and remaining milestones

Run `make check`, `make demo`, `make relay-demo`, and `make segmented-demo`.
The segmented demo verifies 64 matching keys and preserved IDs, delayed final
availability, depletion, independent trust domains, rejected remote identities,
restart replay rejection, and slave retrieval with the master KMS stopped.
Go tests cover atomic batches, malformed responses, lost responses, crashes
between intent and response, role errors, expiry, replenishment of the model,
ID collisions, journal ownership and fail-closed persistence errors.

The provider emulator is disposable and loses state on restart; national KMS
journals are durable. Partner failover/recovery and independent conformance are
not established by these tests. No production application protocol is implemented.

Terrestrial 020 interworking and hop-by-hop/multipath remain separate laboratory
capabilities. An SDN-facing metadata abstraction is still planned. An external
SDN controller is not needed for this segmented retrieval flow.
