# Architecture

Status: initial implementation baseline, 2026-09-11.

The [shared design](https://chatgpt.com/share/6aa4058f-4374-83ed-b1ff-e6af5d5267f9)
calls for a standalone interoperable KMS before EAGLE-1 and SDN integration.
This baseline implements its first runnable application-facing slice.

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
wire models and errors; the repository owns atomic lifecycle operations. A
future database implementation must provide the same transaction semantics.

The local laboratory uses one KMS with two authorized SAE identities. Each key
has two delivery records, one for the master and one for the slave. This is a
test fixture for application delivery, not a transport across QCI domains.
Synthetic ingestion binds a key to an ordered SAE pair in advance; dynamic
pool-to-association assignment is deferred.

## Target interworking architecture

```text
SAE-LU --014--> LU KMS --020--> EAGLE-LU
                                  |
                          EAGLE-1 domain
                                  |
SAE-GR --014--> GR KMS --020--> EAGLE-GR
```

Germany and Ireland follow the same adapter pattern. ETSI 020 belongs at the
local interworking node. It is not a replacement for the satellite domain's
internal key establishment. Consult [ETSI020_PROFILE](ETSI020_PROFILE.md).

An EAGLE-1 adapter will use the same KMS core. Actual peer identities, endpoint
profiles, certificate policy, timeout behavior, and interoperability test
vectors must be supplied before connecting to the real service.

## Trust boundaries

1. Network callers cross a TLS boundary. Only verified certificates with exactly
   one configured URI SAN identify an SAE. Headers and certificate CNs do not.
2. An ordered master/slave allowlist authorizes each request and key record.
3. The repository is trusted with material. Only explicit delivery operations
   return bytes; metadata/status types cannot contain material.
4. Test provisioning is an in-process startup operation, not a public API.
5. Any future controller receives inventory, associations, alarms and commands
   only. There is no raw-key management endpoint.

## Failure semantics

Reserve a complete batch atomically. Consume a complete reservation before
serializing its response. A failed/lost response does not restore a key. A
reservation interrupted before consumption remains reserved until expiry or
explicit invalidation. This sacrifices availability to prevent unintended
reuse. Durable transactions, acknowledgement recovery and crash-safe
tombstones are required before using persistent or external sources.

Memory clearing is best effort; Go and TLS/JSON buffering do not guarantee
physical erasure. The repository has a hard lifetime capacity including
tombstones. Restarting clears all state and is safe only for this synthetic lab.
