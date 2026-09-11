# TransEuroOGS KMS development

Follow the specifications under `docs/` and the milestone boundaries in
`docs/DEVELOPMENT_PLAN.md`. Keep the key plane independent of SDN and protocol
handlers independent of lifecycle/storage logic.

- Use only synthetic key material in development and tests.
- Never commit or log real QKD keys, private keys, credentials, or certificates.
- Use established cryptographic libraries; do not invent cryptographic protocols
  or primitives. Test-PKI generation uses the Go standard library.
- Preserve atomic reservation, per-recipient single delivery, expiry, and
  duplicate-ID rejection. Do not silently return burned keys to the pool.
- Keep persistence behind the core repository interface.
- Add meaningful automated tests for every behavior change, especially races,
  authorization, partial failure, and replay.
- Run `make check` and `make demo` before completing implementation work.
- Do not label a profile or emulator as standards conformant without independent
  conformance evidence. EAGLE-1 behavior requires its actual interface agreement.
- Do not change the architecture or protocol requirements unless requested.
