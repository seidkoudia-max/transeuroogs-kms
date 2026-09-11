# ETSI 020 asynchronous laboratory profile

Implemented for ETSI GS QKD 020 V1.1.1 (June 2026). The upstream revision,
license and checksum are pinned in [`api/etsi020`](../api/etsi020/README.md).
This is a tested project profile, without a claim of independent conformance
or compatibility with the real EAGLE-1 service.

## Scope and wire behavior

ETSI 020 exchanges keys between KMSs at a shared trusted interworking site.
The QKD network's internal key establishment and transport are outside its scope.
The prototype distinguishes standard interworking links (`etsi020`) from
explicit synthetic intradomain links (`lab-relay`). Both use mutually
authenticated TLS 1.3; only the former uses ETSI paths.

| Operation | Standard endpoint | Implemented behavior |
| --- | --- | --- |
| Versions | GET `/kmapi/versions` | `versions: ["v1"]`; no optional synchronous capability advertised |
| Transfer | POST `/kmapi/v1/ext_keys` | Persist complete validated batch, then 202; asynchronously ACK each key |
| Acknowledge | POST `/kmapi/v1/ext_keys/ack` | Top-level ACK array; partial/mixed key groups; commit before 200 |
| Void | POST `/kmapi/v1/ext_keys/void` | Persist discard and propagation intent, then 202; asynchronous result |

Lab endpoints are `/lab/versions`, `/lab/v1/relay/keys`, and the latter followed
by `/ack` or `/void`. They reuse the tested message/lifecycle adapter for the
synthetic lab only. They are not another ETSI interface.

Profile limits and decisions:

- One configured initiator/target SAE pair per transfer; only one target.
  SAE IDs are bounded to 64 ASCII URI characters with percent escapes.
- 256-bit values, canonical base64, lowercase UUIDv4 key IDs, at most 128
  keys per transfer; ACK/void arrays are bounded by the published 1,024 limit.
  Other UUID versions and key sizes remain outside this project profile.
- `ack_callback_url` is required. It must exactly equal the authenticated
  peer's configured HTTPS URL and its mode-specific ACK path. No redirects,
  arbitrary callback hosts, URL credentials or header-supplied identities.
- Peer certificates require normal chain/hostname validation and exactly one
  matching configured URI SAN. SAE certificates cannot invoke 020; KME
  certificates cannot retrieve SAE keys. Intermediates expose no SAE identity.
- Unknown mandatory extensions return 503 with
  `details.unsupported_mandatory_extension`. Unknown optional transfer
  extensions and per-key extensions retain their JSON values through relay.
  Opaque JSON may include null values; duplicate JSON members are rejected.
- Extension names require the published `E<PEN>_...` convention. The project
  defines no proprietary extension and claims no PEN. `E32473_fixture` is used
  only as a documentation/test fixture.
- Errors use RFC 9457 `type`, `status`, `title` and string-valued `details`.
  Malformed bodies return 400, unauthorized peers/pairs/callbacks 401,
  unsupported profile options or capacity failures 503. Neither 400 nor 401
  commits newly created key associations.
- Void with empty `key_ids` requires `all_confirmation: true`; selection is
  restricted to that association and peer. Unknown IDs receive persistent
  tombstones before `key not present` is acknowledged. A late transfer cannot
  reintroduce them. Empty matching selections receive an empty ID ACK.

## Transfer and recovery

The network repository records source, intermediate and destination roles.
The origin exposes a key through 014 only after the destination's `relayed`
acknowledgement has returned through every hop. The destination can deliver
its authorized copy once by ID. Intermediates clear material after downstream
acknowledgement and retain transfer/replay metadata. An intermediate cannot
retrieve or allocate that material as an SAE.

Each node persists outbound intent **before sending** and acceptance **before
202**. An identical retry is idempotent. Different material, extensions or
association cannot overwrite an existing ID. Outbound ACK jobs survive restart;
duplicate ACKs cannot restore consumed or voided keys. SAE consumption commits
before serialization, so a lost SAE response still burns that delivery right.

Static routes distribute distinct keys round-robin. A read-only versions probe
can choose another configured path before the first POST. Once outbound intent
is committed, that key stays pinned to the selected peer through every network
error and restart. Even a later rejection does not erase earlier uncertainty.
This trades availability for protection against duplicate paths. There is no
secret sharing, threshold reconstruction or path combining.

Void and expiry discard locally, persist propagation toward the other adjacent
KMSs, and retain tombstones. `failed to void` propagates if a recipient already
consumed its copy. Failed transfers initiate voiding. Late `relayed` messages
cannot revive a voided record. Retries continue while the service is running;
an offline peer can leave a pending transfer/void indefinitely. There is no
operator API to force an uncertain ID onto another path.

Inbound keys have a fixed one-hour local lifetime starting at first acceptance;
retries do not extend it. Source TTL is configurable and its expiry propagates
void. The standard message has no expiry field: a shared absolute expiry needs
an agreed extension. There is no bounded global revocation during a partition.

## Persistence and operating limits

Every node uses an independent directory, mode 0700, with exclusive process
locking. `state.enc` contains versioned AES-256-GCM snapshots using Go's random
nonce AEAD. The local wrapping key and state files are mode 0600. Writes use
temporary files, file fsync, atomic rename and directory fsync. A failed write
poisons the process; delivery fails closed. Corrupt, missing established state,
wrong wrapping keys and incompatible configurations fail startup.

Keep both `wrapping.key` and `state.enc`. Restart with the same configuration
and `--synthetic-keys=0`. Provisioning a populated network journal is rejected.
Configuration binding requires a future migration mechanism for policy changes;
editing routes while reusing a journal fails startup. Interrupted reservations
remain reserved until expiry; they are never returned to the available pool.

This is single-process laboratory persistence on local Unix filesystems, not
HA storage. Full snapshots and terminal records count against lifetime capacity;
there is no tombstone garbage collection. The wrapping key shares the host
with encrypted state, so this does not protect against host compromise or a
rollback of both files. Operational database transactions, protected wrapping
keys, anti-rollback protection, certificate management, audit and admission
control remain future work. Do not provision real QKD material.

## Demonstration and SDN

`make relay-demo` runs independently configured binaries over real TLS:

The EAGLE names below are synthetic interworking fixtures. The actual integration
target is the SES ground service's published 014 interface, with satellite-owned
offline relay; see [EAGLE1_INTEGRATION](EAGLE1_INTEGRATION.md). This diagram does
not describe the SES service or satisfy the segmented upstream 014 milestone.

```text
SAE-LU --014-- LU --020-- EAGLE-LU
                              |--lab relay-- relay-a --lab relay--|
                              |--lab relay-- relay-b --lab relay--|
                                                               EAGLE-GR --020-- GR --014-- SAE-GR
```

It verifies a direct two-KMS transfer, 24 matching keys split 12/12 across the
two paths, eight keys through the surviving path when relay-a is unavailable,
role isolation, ready-state recovery after SIGKILL and consumed-key replay rejection after
restarts. Fault-injected Go tests cover lost responses/ACKs, uncertain transfer
pinning, void propagation, expiry, conflict atomicity and concurrent delivery.

An SDN controller is **not required for these static paths**. An SDN-facing
metadata abstraction remains a project requirement. A future controller
can use topology, link capacity and key-pool metadata to choose routes and
perform admission control. It must not receive key bytes. Live policy changes,
QKD link-key consumption/OTP relay, dynamic topology, and actual EAGLE-1
interoperability require separate adapters and validation.
