# ETSI 014 laboratory profile

Baseline: [ETSI GS QKD 014 V1.1.1 (2019-02)](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf),
clauses 5–6. This implementation is a restricted prototype pending independent
conformance testing.

The implemented contract is available as [OpenAPI](../api/etsi014/openapi.json).

| Method | Path |
| --- | --- |
| GET | `/api/v1/keys/{slave_SAE_ID}/status` |
| GET, POST | `/api/v1/keys/{slave_SAE_ID}/enc_keys` |
| GET, POST | `/api/v1/keys/{master_SAE_ID}/dec_keys` |

Wire models use the standard field spellings, UUID key IDs and Base64 material.
The profile fixes key size at 256 bits and limits batches to 128. Defaults are
one key and 256 bits. GET retrieval by ID accepts one ID; POST accepts a batch.
Multicast is disabled. Unknown mandatory extensions fail; optional extensions
may be ignored. Unsupported non-byte sizes receive a specific error.

TLS 1.3 and mutual certificates are required. Identity comes from the verified
leaf certificate's configured URI SAN. Status and delivery require an allowed
ordered association. The target KME in this local fixture is the same KME.

Project policy: malformed inputs return 400, unauthorized requests 401, and
unavailable/consumed/expired inventory 503. Transport guards additionally use
413/415 for oversized or non-JSON bodies and 405 for unsupported methods.
All responses disable caching. Validation precedes allocation.

Both local delivery records must be consumed once. Response loss burns the
corresponding delivery; retries do not reissue it. Request-body limits are
64 KiB; duplicate JSON members, trailing JSON, explicit nulls and unknown
top-level parameters are rejected to keep this profile unambiguous.

Limitations: no multicast, variable sizes, vendor extensions, remote key
establishment, persistent recovery or external interoperability evidence.
The same-node demonstration does not establish end-to-end QCI security.

This document describes our application-facing server. The segmented EAGLE-1
adapter adds an upstream client and durable local ingestion, specified in
[EAGLE1_INTEGRATION](EAGLE1_INTEGRATION.md). The limits above are our laboratory
choices and must not be attributed to the SES deployment without its profile.
