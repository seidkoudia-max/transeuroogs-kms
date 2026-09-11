# Verification map

Go tests live alongside their packages in `src/`. Run `make check` with a C
compiler available for the Go race detector. `make demo` runs the built server
and Python SAE harness over real mTLS, with no HTTP mocks.

| Requirements | Test groups |
| --- | --- |
| CORE-001, CORE-007 | `TestKeyValidationAndRedaction`, `TestUUIDs`, `TestSingleDeliveryAndTombstone` |
| CORE-002, CORE-004 | `TestSingleDeliveryAndTombstone`, `TestConcurrentSlaveReplay` |
| CORE-003 | `TestConcurrentAllocationNoReuse` (1,000 keys, 32 workers) |
| CORE-005 | `TestExpiryAndInvalidation`, `TestSlaveExpiryAfterMasterDelivery` |
| CORE-006 | `TestBatchAtomicityAndAssociation`, `TestLostResponseBurnsDelivery` |
| API-001, API-003 | `Test014StatusAndMatchingDelivery`, `Test014BatchAndOptionalExtensions` |
| API-002, SEC-004 | `Test014ValidationDoesNotAllocate`, `TestJSONContentType`, `TestCapacityAndValidation` |
| SEC-001, SEC-002 | `TestLiveMutualTLS`, `TestIdentityNeverTrustsHeadersOrUnverifiedCertificates` |
| SEC-003 | redaction tests; demo outputs no key bytes |
| LAB-001 | `TestSyntheticSource`, configuration tests, explicit CLI flag |
| LAB-002 | `emulator/sae/demo.py` |
| OPS-001 | `.github/workflows/ci.yml` |

These are project acceptance tests, not independently certified ETSI conformance
tests. Full 020/interoperability and production recovery suites remain planned.
