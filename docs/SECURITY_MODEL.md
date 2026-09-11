# Security model

Only a synthetic, ephemeral laboratory is supported. Test credentials are
generated locally, excluded from Git and expire after 24 hours. Certificate
generation uses standard-library Ed25519 and X.509; no custom cryptography.
The test CA private key is not written to disk.

| Threat | Baseline control | Remaining work |
| --- | --- | --- |
| Unauthenticated caller / MITM | mTLS, trusted CA, TLS 1.3, normal hostname verification | operational PKI, certificate lifecycle/revocation |
| Wrong SAE / spoofed header | exact URI SAN mapping and ordered pair authorization | managed identities and policy review |
| Key reuse / parallel requests | repository lock, transactional batches, terminal states | durable database transactions and recovery |
| Replay / wrong key ID | one-use reservation, per-recipient state and tombstones | persistent replay records and 020 transactions |
| Expired or invalid keys | clock checks on repository operations, discard material | secure lifecycle sweeper with persistence |
| Logging leakage | metadata-only diagnostics, redacted domain values | deployment-wide logging/trace review |
| Resource exhaustion | lifetime capacity, batch/body limits, HTTP timeouts | per-identity rate limits and admission control |
| Memory/process compromise | no claimed protection beyond process isolation | HSM or encrypted storage, host hardening |
| Rollback/restart | no recovery of synthetic state; explicit limitation | crash-safe storage and anti-rollback design |

The master and slave rights are separate, legitimate copies. A master key is
burned before response serialization, and a slave key is burned before its
response. Network failures may therefore lose a key but cannot make it
available again. The application must not retry key requests blindly.

Go memory clearing reduces retained copies but is not guaranteed secure
erasure. JSON and TLS may retain transient copies. No production security,
information-theoretic security, audit immutability, or standards certification
is claimed. An independent security review is required for operational use.

Future SDN metadata must never carry raw keys. An eventual 020 callback client
must restrict destinations to authenticated, configured peers to avoid SSRF.
