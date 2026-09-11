# ETSI 020 integration boundary

Status: planned; no 020 protocol handler or claimed emulator conformance yet.

Use the published [ETSI GS QKD 020 V1.1.1 source](https://forge.etsi.org/rep/qkd/gs020-interop-kms/-/tree/v1.1.1)
and its [OpenAPI description](https://forge.etsi.org/rep/qkd/gs020-interop-kms/-/blob/v1.1.1/interop-kms_ExtraMarkup.yaml).
The published baseline includes asynchronous acknowledgement; implementing a
generic synchronous transfer endpoint would not establish conformance.

The adapter will handle keys at a shared, trusted interworking site. It must
cover version/capability negotiation, external key requests, acknowledgement,
voiding, caller/target identities and the full published schema. The exact
wire contract must be pinned and tested before implementation.

Acceptance work:

1. Record the published source revision and build schema-based test vectors.
2. Define durable local/peer transaction ownership and allowed lifecycle states.
3. Implement required asynchronous behavior and callback destination allowlists.
4. Test duplicate transactions, conflicting ID/material, partial acknowledgement,
   lost request/ACK, retry, void, expiry and crash recovery.
5. Run independently configured KMS binaries at the interworking site.
6. Obtain the EAGLE-1 endpoint, supported profile, IDs, PKI policy, error/timeout
   agreement and test access; reconcile differences in an isolated adapter.

The emulator must never be presented as the real EAGLE-1 system. Cross-domain
distribution inside the satellite segment remains outside this local API.
