# Synthetic QKD source

The initial source is `src/internal/synthetic`. Opt in with the KMS
`--synthetic-keys N` flag. It creates independent random 256-bit test values
and UUIDs using Go's `crypto/rand`, then calls `Repository.StoreKey` in-process.
The first configured ordered SAE pair receives these keys.

No unauthenticated ingestion endpoint exists. This source does not simulate
QBER, optics, finite-key effects, or real quantum key establishment. Replace it
behind an authenticated provisioning boundary only after persistence is ready.
