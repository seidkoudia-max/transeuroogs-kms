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
| NET-001 | `TestWireValidationAndAuthorization`, `TestRealMTLSIdentityPinningAndNoRedirect`, `TestPinnedUpstreamContract` |
| NET-002, NET-004 | `TestLostAcknowledgementOutboxSurvivesRestart`, `TestPreflightFailoverAndUncertainTransferPinned`, `TestAtomicConflictDuplicateAndPartialAcknowledgements` |
| NET-003, LAB-003 | `TestMultipathEndToEndAndRestart`, `emulator/network/demo.py` |
| NET-005 | `TestVoidPropagationLateAckUnknownAndConsumed`, `TestExpiryAndConcurrentSingleDelivery`, `TestOptionalExtensionsPreservedAndOwned` |
| NET-006 | `TestJournalLockCorruptionMissingStateAndFailClosed` |
| OPS-001 | `.github/workflows/ci.yml` |

These are project acceptance tests, not independently certified ETSI conformance
tests. Independent 020 conformance, partner interoperability, power-loss/filesystem
fault campaigns and production recovery validation remain future work.

`make relay-demo` verifies separate KMS processes, real TLS and encrypted state.
The fault-injected Go network tests complement it with controlled lost responses,
lost ACKs, partitions and delayed operations. They do not simulate QKD physics.
