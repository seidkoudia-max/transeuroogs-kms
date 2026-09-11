# Architecture

Status: implemented laboratory and agreed EAGLE-1 integration target, 2026-09-11.

The [shared design](https://chatgpt.com/share/6aa4058f-4374-83ed-b1ff-e6af5d5267f9)
calls for a standalone interoperable KMS before EAGLE-1 and SDN integration.
The service now includes local application delivery and a separate durable
network repository implementing the asynchronous 020 laboratory profile.

```text
SAE-LU / SAE-GR laboratory clients
                  | mTLS, ETSI 014 profile
             HTTP adapter
                  | authenticated SAE + validated request
          Core repository contract
                  |
       Atomic in-memory key repository
                  ^
     Opt-in synthetic source at startup
```

The service is one Go binary with modular packages. `src/internal/core` has no
HTTP, TLS, database, or orchestration dependencies. The HTTP adapter translates
wire models and errors; the repository owns atomic lifecycle operations. The
optional PostgreSQL implementation preserves the same transaction semantics.

The local laboratory uses one KMS with two authorized SAE identities. Each key
has two delivery records, one for the master and one for the slave. This is a
test fixture for application delivery, not a transport across QCI domains.
Synthetic ingestion binds a key to an ordered SAE pair in advance; dynamic
pool-to-association assignment is deferred.

## Interworking architecture

The project owner confirmed that our gateway is authorised and the SES-provided,
SES-certified receiver and terrestrial QCI end node share a trusted environment.
The satellite performs point-to-point distribution followed by offline relay.
We deploy the same national KMS software in LU, GR, DE and IE.

The target integration uses the SES ground service's published I/F G, ETSI 014:

```text
SES ground key service LU <--014 client-- adapter -- LU KMS --014--> SAE-LU
           |
 EAGLE-1 satellite service: separate contacts, offline relay
           |
SES ground key service GR <--014 client-- adapter -- GR KMS --014--> SAE-GR
```

The segmented synthetic profile now implements these local 014 client boundaries
and durable delivery. EAGLE-1 is treated as a black box responsible for OGS
authentication, point-to-point establishment, offline satellite relay and paired
keys/IDs. This is the agreed service contract; the lab does not verify SES internals.

Master/slave are per-association retrieval roles. The configured master gateway
uses `enc_keys`; its corresponding slave gateway uses `dec_keys` by the same KID.
Our national KMS serves local applications through its separate 014 server. The
application workflow carries the selected KID to the other application; no
inter-country KMS control connection is required for this baseline. Local mTLS
and provider trust do not replace the consuming application's security protocol.

ETSI 020 remains a local trusted-site KMS interworking option where both peers
support it. The `make relay-demo` EAGLE-named processes remain generic synthetic
020 stand-ins. `make segmented-demo` instead exercises the published SES 014
boundary with independent local and provider trust stores. Terrestrial relay and
multipath are separate from the satellite service's internal implementation.

The same adapter serves each national deployment with an explicit local role,
upstream identity/pair and private journal. Only the synthetic profile is enabled;
real service identities, credentials, limits and lifecycle behaviour still need
the deployment profile. See [EAGLE1_INTEGRATION](EAGLE1_INTEGRATION.md) for the
implemented boundaries, failure semantics and acceptance evidence.

## Trust boundaries

1. Network callers cross a TLS boundary. Only verified certificates with exactly
   one configured URI SAN identify an SAE. Headers and certificate CNs do not.
2. An ordered master/slave allowlist authorizes each request and key record.
3. The repository is trusted with material. Only explicit delivery operations
   return bytes; metadata/status types cannot contain material.
4. Test provisioning is an in-process startup operation, not a public API.
5. Any future controller receives inventory, associations, alarms and commands
   only. There is no raw-key management endpoint.
6. The SES receiver's certification is an external component property, not
   certification of this KMS. Co-location preserves authenticated service
   boundaries and separate upstream gateway/downstream application identities.

## Failure semantics

Reserve a complete batch atomically. Consume a complete reservation before
serializing its response. A failed/lost response does not restore a key. A
reservation interrupted before consumption remains reserved until expiry or
explicit invalidation. This sacrifices availability to prevent unintended
reuse. Network mode adds durable transactions, acknowledgement recovery and
crash-safe tombstones through `relay.Engine`, implementing the same core
repository contract. `etsi020` translates the peer wire protocol; `peering`
holds static policy independently of a controller.

Memory clearing is best effort; Go and TLS/JSON buffering do not guarantee
physical erasure. The repository has a hard lifetime capacity including
tombstones. The memory fixture clears state on restart. Network mode uses an
independent AES-GCM journal per node and preserves terminal records. Its local
wrapping key is laboratory protection, without host-compromise or rollback
resistance. See [ETSI020_PROFILE](ETSI020_PROFILE.md) for the implemented
six-node topology and durability boundaries.

## Operational persistence and consuming application

The optional `operational` configuration supplies a `durable.Store` to the local,
segmented or relay repository. PostgreSQL stores a transactionally consistent
encrypted snapshot, an allowlist of public metadata and append-only audit events.
Lifecycle logic remains in its repository; no protocol handler issues SQL. A
separate checkpoint fences old database restores. Only one writer serves each
namespace; deployment HA must preserve committed state and checkpoint ownership.

The standalone reference SAE supplies the application's authenticated KID
notification over mTLS, followed by OpenSSL TLS 1.3 PSK key confirmation within
that stream. It contacts only its own KMS for key material. Its metadata ledger
never stores key bytes. This application channel does not introduce KMS-to-KMS
control traffic into the segmented baseline. See [OPERATIONS](OPERATIONS.md) and
[APPLICATION_INTEGRATION](APPLICATION_INTEGRATION.md).
