# Security model

Only a synthetic laboratory is supported; network state persists across restarts. Test credentials are
generated locally, excluded from Git and expire after 24 hours. Certificate
generation uses standard-library Ed25519 and X.509; no custom cryptography.
The test CA private key is not written to disk.

| Threat | Baseline control | Remaining work |
| --- | --- | --- |
| Unauthenticated caller / MITM | mTLS, trusted CA, TLS 1.3, normal hostname verification | operational PKI, certificate lifecycle/revocation |
| Wrong SAE / spoofed header | exact URI SAN mapping and ordered pair authorization | managed identities and policy review |
| Key reuse / parallel requests | repository lock, atomic batches, durable network terminal states | production database/HA transactions |
| Replay / wrong key ID | one-use reservation, per-recipient state, durable 020 replay records | operational retention/anti-rollback |
| Expired or invalid keys | delivery clock checks, durable network expiry/void sweeper | agreed global expiry across domains |
| Logging leakage | metadata-only diagnostics, redacted domain values | deployment-wide logging/trace review |
| Resource exhaustion | lifetime capacity, batch/body limits, HTTP timeouts | per-identity rate limits and admission control |
| Memory/process compromise | local AES-GCM journal, restrictive file permissions | HSM-backed wrapping key, host hardening |
| Rollback/restart | fsync/rename journal, process lock, fail-closed recovery | anti-rollback and backup/HA design |

The master and slave rights are separate, legitimate copies. A master key is
burned before response serialization, and a slave key is burned before its
response. Network failures may therefore lose a key but cannot make it
available again. The application must not retry key requests blindly.

Go memory clearing reduces retained copies but is not guaranteed secure
erasure. JSON and TLS may retain transient copies. No production security,
information-theoretic security, audit immutability, or standards certification
is claimed. An independent security review is required for operational use.

SDN metadata must never carry raw keys. The 020 callback client restricts
all destinations to authenticated, configured peer URLs, pins the peer URI SAN
and refuses redirects. Network roles isolate local SAE access from KME access.
Once sent, an uncertain key remains on its selected path through retries and
restarts. This prevents blind failover from creating duplicate path ownership.

The journal wrapping key lives on the same host as state. Encryption does not
protect against host compromise or restoring old copies of both files. Keep
both files together; deleting established state fails startup. A full loss of
the entire directory cannot be distinguished from fresh laboratory provisioning.
Intermediate nodes are trusted with clear key material; the lab relay is mTLS,
without QKD link-key consumption, OTP wrapping or information-theoretic claims.
