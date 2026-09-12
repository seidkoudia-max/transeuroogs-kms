# Authenticated application KID notification

`src/application/session.py` is a runnable reference SAE integration with a
library callback for a consuming application. It keeps the agreed three-segment
KMS architecture. Application-to-application communication is a separate security
session; it does not add a cross-country KMS control link or recreate SES relay.

## Flow

1. The initiating application commits a local attempt before calling local
   ETSI 014 `enc_keys`. It stores the returned KID in its metadata-only ledger.
2. It opens TLS 1.3 with the peer application, requiring a CA-verified client and
   server certificate, hostname verification, current issuer CRLs and the exact
   configured peer URI SAN. Credentials are separate from local KMS credentials.
3. It sends the session ID, KID, ordered SAE pair, both application identities and
   a short expiry over that authenticated stream. No key material is transmitted.
4. The receiver verifies every binding, durably records the session/KID before
   consumption, and retrieves the same KID from its own national KMS.
5. Over the existing mTLS stream, both applications run a second, standard TLS 1.3
   handshake using the retrieved 256-bit value as a one-session external PSK.
   OpenSSL verifies the handshake Finished messages. A mismatched key or PSK
   identity fails; matching KIDs alone never establish key equality.
6. Inside the PSK-protected stream they check the complete session context and
   record confirmation. Optional application callbacks can then use the stream.

The outer mTLS connection authenticates application identities. The inner TLS
handshake confirms possession of the key. The TLS stack performs all handshake,
key derivation and record protection operations. This is a reference application
profile using [TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html) and the
[external-PSK guidance](https://www.rfc-editor.org/rfc/rfc9257.html), not a new
cryptographic primitive or an ETSI application-notification standard. No claim of
information-theoretic security or exclusion of trusted KMS/provider nodes is made.

Each QKD key is dedicated to one application association and one PSK session.
The PSK identity includes the session UUID and unchanged KID; both endpoint
identities are checked in the protected context. TLS 1.2, certificate fallback
in the inner session, resumption tickets and early application data are disabled.
The outer session also keeps PSK identities out of cleartext network traffic.
An external PSK importer is not implemented; do not reuse these keys with another
TLS version, protocol, hash profile, application pair or role.

## Configuration

Each application has an explicit `master` or `slave` role and its own state
directory, local KMS credentials and peer application credentials. A generated
working example is in [the operational demo](../emulator/operational/demo.py).
Its test certificates use the existing lab URI names; deployments provision
dedicated application identities through their operational CA.

```json
{
  "role": "master",
  "identity": "urn:transeuroogs:app:lu",
  "peer_identity": "urn:transeuroogs:app:gr",
  "master": "SAE-LU", "slave": "SAE-GR",
  "peer_host": "application.gr.example", "peer_port": 9443,
  "state_dir": "/var/lib/qci-app/sessions",
  "tls": {
    "application": true,
    "ca": "/run/app-pki/peer-ca.pem", "crls": ["/run/app-pki/peer-issuer.crl.pem"],
    "cert": "/run/app-pki/identity.crt.pem", "key": "/run/app-pki/identity.key.pem"
  },
  "kms": {
    "url": "https://kms.lu.example:8443", "identity": "urn:transeuroogs:kme:lu",
    "ca": "/run/local-kms-pki/ca.pem", "crls": ["/run/local-kms-pki/issuer.crl.pem"],
    "cert": "/run/local-kms-pki/sae.crt.pem", "key": "/run/local-kms-pki/sae.key.pem"
  }
}
```

The receiver config uses `role: slave`, reverses application identities and
points to its own local KMS and credentials. It retains the same ordered SAE pair.

For a federation-enabled KMS, configure the application's `pool` object with
the exact local `pool_id`, `remote_pool_id`, `binding_revision`, `service_id`,
`service_epoch` and `purpose` from its KMS registry. Version 2 notifications
authenticate both pool names and the common service/epoch/purpose; local revisions
are pinned independently in each application ledger. A configured pool rejects
version 1 notifications. See [REMOTE_QCI_UPGRADES](REMOTE_QCI_UPGRADES.md).

After key confirmation, this mode sends a `confirmed` receipt to the local KMS
and checks the pool's current hold before invoking the application callback.
It records `retired` when leaving that callback. A durable outbox preserves each
receipt ID across lost replies/restart and flushes in order. These are authenticated
application reports, not proof of commercial-device erasure. The callback must
bound its session duration and handle incident-driven rekeying in its own
application integration; the one-time gate check cannot interrupt an already
running callback or revoke previously delivered bytes.

```sh
python3.14 src/application/session.py --config receiver.json --listen 0.0.0.0 --port 9443
python3.14 src/application/session.py --config sender.json
```

Both CLI operations print only session metadata or redacted errors. No key
bytes, hashes or TLS session secrets are logged, including when `SSLKEYLOGFILE`
is set. The module constructs SSL contexts directly rather than enabling the
environment-controlled key logger. Python 3.13+ with `ssl.HAS_PSK` is required;
the [Python ssl API](https://docs.python.org/3.14/library/ssl.html) supplies the
PSK callbacks and memory-BIO interface.

For a consuming application, use `send_session(..., application=callback)` and
`receive_session(..., application=callback)`; the callback receives the confirmed
stream and bound session metadata. It must implement its own bounded business
messages and timeout/error handling. The reference CLI only confirms a session;
no particular commercial encryptor, VPN or business application is integrated.

## Failure semantics and limits

The SQLite ledger stores IDs, expiry and uncertain/confirmed state, never keys.
It uses full synchronous transactions and unique session/KID constraints. Unknown
master allocations, interrupted requests, duplicate notifications and failed
confirmations are terminal attempts. There is no automatic retry or recovery of
key bytes and no restart-time key cache. Start a new session with a fresh key.
The lifetime capacity is 100,000 attempts; tombstone garbage collection is absent.

Context and expiry are bound before confirmation. The receiver may record a
confirmation that the client never receives; the client then retains an uncertain
attempt. This never authorizes key reuse. Python/OpenSSL may retain transient
copies in memory; buffer clearing is best effort, not guaranteed secure erasure.

The reference receiver serializes bounded sessions with timeouts. Application HA,
large-scale load handling, business payload integration and deployment certificate
issuance need the chosen application's environment. Cross-state trust bundles
must be explicitly provisioned; the laboratory does not establish a national
or European trust federation automatically.

`make app-test` checks native TLS success, wrong-key/wrong-identity rejection,
durable concurrent/restart replay prevention and expiry/association validation.
`make operational-demo` exercises separate application processes over real mTLS
with two PostgreSQL-backed KMSs and the synthetic Eagle-1 service.
