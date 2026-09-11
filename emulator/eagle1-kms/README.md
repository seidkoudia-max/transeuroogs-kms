# EAGLE-1 segmented laboratory

Run `make segmented-demo` for the agreed three-segment model:

```text
QCI-LU -- local authenticated service --> OGS-LU
                 [EAGLE-1 black-box segment]
QCI-GR -- local authenticated service --> OGS-GR
```

Two national KMS processes act as upstream ETSI 014 clients, using master/slave
roles for one gateway/application association. A separate `eagle-emulator` process
exposes the two ground-service interfaces and models delayed paired-key
availability with synthetic values. It does not implement satellite or QKD
cryptography, or validate SES's internal authentication.

The harness generates three independent test CAs, verifies local certificate and
role enforcement, retrieves 64 matching keys with unchanged IDs, checks depletion
and rejects replay after process crashes/restarts. Slave retrieval succeeds while
the master KMS is stopped. Only counts and verification results are printed.
Application KID notification is performed inside the harness; production
application authentication and notification are outside this demo.

`demo.py` generates the complete example national configurations in a temporary
directory. `--pki-dir` supplies each national KMS's local server/application trust;
`eagle.pki_dir` supplies its separate provider trust and gateway credential. The
only accepted upstream profile is `synthetic-segmented-v1`. See
[EAGLE1_INTEGRATION](../../docs/EAGLE1_INTEGRATION.md) for roles, lifecycle limits,
configuration fields and the remaining SES deployment inputs.

The national journals are durable. The provider emulator is disposable and must
remain running during national KMS restarts; provider restart loses its synthetic
inventory. Go tests separately exercise lost responses, uncertain intents,
malformed batches, expiry, model replenishment and failed persistence.

## Existing generic interworking stand-ins

`make relay-demo` still creates independent `eagle-lu` and `eagle-gr` KMS processes
speaking our bounded 020 profile through `relay-a` or `relay-b`. Those are generic
interworking fixtures, not the SES service boundary. Their terrestrial trusted
relay test is separate from the segmented demo. See
[ETSI020_PROFILE](../../docs/ETSI020_PROFILE.md).
