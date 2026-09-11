# EAGLE-domain laboratory stand-ins

`make relay-demo` creates independent `eagle-lu` and `eagle-gr` KMS processes
with distinct PKI identities and encrypted journals. They speak the bounded
ETSI 020 profile to LU/GR and the explicit lab relay protocol inside the
synthetic domain, through `relay-a` or `relay-b`.

These names illustrate an interworking boundary. They are not the real EAGLE-1
service, an implementation of its private network protocol, or a satellite
simulation. Actual endpoints, certificate policies, routing/key protection and
partner test vectors are still required for integration. See
[ETSI020_PROFILE](../../docs/ETSI020_PROFILE.md).
