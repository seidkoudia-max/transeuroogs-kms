# ETSI GS QKD 020 V1.1.1 baseline

`upstream/interop-kms_ExtraMarkup.yaml` is the unmodified published contract.
Its BSD 3-Clause license is retained in `upstream/LICENSE`.

- Source: https://forge.etsi.org/rep/qkd/gs020-interop-kms
- Tag: `v1.1.1`
- Commit: `00e2a7957f75088286947f601b027a6278048f13`
- SHA-256: `300ce31c46452acda4c17542c4e124ec023e975a74ac4f1ddd8cd9f4e71951c6`
- Normative PDF: https://www.etsi.org/deliver/etsi_gs/QKD/001_099/020/01.01.01_60/gs_QKD020v010101p.pdf

The implementation is the bounded laboratory profile documented in
[`docs/ETSI020_PROFILE.md`](../../docs/ETSI020_PROFILE.md). Wire vectors are in
`src/internal/etsi020/http_test.go`; they pin operation names, request shapes,
asynchronous responses, RFC 9457 errors and profile rejection behavior.

Upstream schema caveat: `key_id_container` places `properties` at the array
level instead of inside `items`. Our ACK validator follows the normative prose:
an array of objects, each with required `key_id` and optional `extension`.
The vendor file is preserved exactly. These project vectors are not an
independent conformance suite or proof of interoperability.
