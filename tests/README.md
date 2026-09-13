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
| EAGLE-001, EAGLE-005 | `TestUpstreamClientTLSProfileAndNoRetry`, `TestSegmentedProfileRoleAndIdentityValidation`, segmented demo with three independent CAs |
| EAGLE-002, EAGLE-006, EAGLE-007 | `TestMasterReservationDurabilityAndRoleIsolation`, `TestSlaveAtomicReplayAndRestart`, `TestBindingLockAndProviderCollision`, segmented demo |
| EAGLE-003 | `TestOfflineCompletionAndReplenishment`, segmented demo delayed inventory |
| EAGLE-004 | `TestUncertainSlaveDeliveryNeverRetriesAcrossRestart`, `TestExpiryCapacityAndFailedCommit`, `TestUpstreamMalformedBatchAndLostResponse` |
| OPS-001 | `.github/workflows/ci.yml` |

These are project acceptance tests, not independently certified ETSI conformance
tests. Independent 020 conformance, partner interoperability, power-loss/filesystem
fault campaigns and production recovery validation remain future work.

`make relay-demo` verifies separate KMS processes, real TLS and encrypted state.
The fault-injected Go network tests complement it with controlled lost responses,
lost ACKs, partitions and delayed operations. They do not simulate QKD physics.

`make segmented-demo` verifies local upstream 014 ingestion with a separate
synthetic provider process and two national KMS processes. Its three test CAs
exercise trust separation, and its SIGKILL scenarios verify national journal
recovery. Provider restart and production application authentication are outside
this demo. The harness supplies KID notification and compares synthetic bytes
internally; it prints no key material. A passing result is not SES validation.

## Operational acceptance

`make operational-demo APP_PYTHON=python3.14` requires installed PostgreSQL binaries
and creates its own private Unix-socket cluster. Real database tests are skipped
in `make check` unless `KMS_TEST_DSN` is set; the dedicated CI operational job
runs them explicitly and also runs the application tests and process demo.

| Requirements | Test groups |
| --- | --- |
| OPS-002, OPS-003 | `TestPostgresLifecycleIsolationRestartAndFencing`, `TestPostgresRejectsDatabaseRollback`, `TestPostgresLostConnectionFailsClosed`, `TestRuntimeAndObserverDatabasePrivileges` |
| OPS-004 | `TestKeyRotationAndBinding`, operational process demo |
| SEC-005 | `TestRevocationExpiryAndIssuer`, `TestCSRAndCredentialValidation` |
| SEC-006 | `TestGuardAuditBeforeResponseRateLimitAndLiveCRL` |
| APP-001 | `emulator/operational/demo.py` |
| APP-002 | native OpenSSL success, wrong-key and wrong-identity tests in `src/application/test_session.py` |
| APP-003 | concurrent notification, restart/expiry and association tests in `src/application/test_session.py` |

## Metadata runtime acceptance

`make metadata-demo` extends the independent-CA segmented process test with
separate metadata signing credentials, scoped investigator identities, signed
pagination, restart recovery and offline two-site verification/tracing. It also
rejects application history reads and altered signed evidence. Existing key
delivery contracts and the master-offline scenario still pass.

| Requirements/subset | Test groups |
| --- | --- |
| META-001, META-003 | `TestEvidenceVerificationScopeReplayAndRevocation`, `TestTamperAndTruncationRejectedOnRecovery` |
| META-004, META-005 (delivery only) | `TestPersistentDeliveryRaceAndAmbiguousCommitWithMetadata`, `TestUncertainCommitWithholdsHistoryUntilRecovery` |
| META-007, META-008 | `TestIncidentUsesCustodyInsteadOfGenerationAndFindsDeliveries`, `TestUnknownClocksPartialCoverageAndDistinctPaths`, `TestUpstreamCoverageMustIncludeExactNamespacePairAndKey`, relay metadata test and two-site metadata demo |
| META-009 | `src/internal/metapi/http_test.go`, `TestAtomicHistoryRecoveryAndRedaction`, `TestAttemptAliasesNeverExposeReservationTokens`, real PostgreSQL metadata isolation test |
| META-011 | `TestHistoryCapacityClockAndBindingFailClosed`, `TestOversizedSnapshotFailsBeforeInnerCommit`, bounded API request/response tests and evidence verification |
| META-012 | `emulator/eagle1-kms/metadata_lab.py` with `make metadata-demo` |
| OPS-002/003 with metadata | `TestPostgresMetadataAtomicRecoveryAndPublicIsolation` in the isolated PostgreSQL acceptance suite |

The full META requirements are broader than this executable subset. The SDN and
remote-QCI increments below add policies, incident controls, adapter evidence and
receipts. META-006 standards-based inline negotiation, actual SES translation,
archive/rotation and physical controller provisioning remain pending. See
[METADATA_PROFILE](../docs/METADATA_PROFILE.md) for the coverage
table and [METADATA_RUNTIME](../docs/METADATA_RUNTIME.md) for runtime limits.
# SDN allocation increment

`make sdn-demo` exercises the pinned TeraFlow v7 Device driver contract against
a separate KMS process over verified mTLS. It checks scoped inventory, policy
reconciliation with a durable outbox, lost command replies, concurrent replay,
restart, controller/key-plane identity separation, signed command events and
continued delivery under local policy without a controller connection.
`tests/validate_sdn_yang.py` validates the captured `.local/sdn-node.json` against
the published 015 V2.1.1 modules, with negative schema cases.

Go allocation tests cover reserved-batch rechecks, unknown generation/evidence,
provider responses aging beyond local TTL, atomic command persistence failure,
revocation scopes, stale revisions, route changes during probes and pinned
uncertain sends after restart. PostgreSQL acceptance checks policy/history
recovery and exclusion of private policy history from coarse metadata views.
Full TFS cluster, real physical telemetry and 021/023 conformance are not tested
by these fixtures; see [SDN_ALLOCATION](../docs/SDN_ALLOCATION.md).

## Remote-QCI protection acceptance

`make federation-demo` runs the three-segment synthetic service with different
local pool names/revisions, explicit unresolved SES inputs and durable operator
holds. `make operational-demo` also verifies pool-bound application confirmation,
retirement receipts and their recovery on real PostgreSQL. All keys are synthetic.

| Boundary | Tests |
| --- | --- |
| Pool isolation, incident/delivery race, no resurrection | `src/internal/storage/protection_test.go`, `src/internal/federation/state_test.go`, federation demo |
| Provider signature/scope/expiry, non-consuming reconciliation | `src/internal/federation/state_test.go`, `src/internal/ingest/protection_test.go` |
| API role isolation and signed protection history | `src/internal/fedapi/http_test.go`, `src/internal/metadata/protection_test.go` |
| Pool notification downgrade and durable receipt outbox | `src/application/test_pool.py`, operational demo |
| Link consumption per hop, protected mTLS, tamper and lost handoff/reply | `src/internal/qkdrelay/*_test.go`, including Windhof–JFK–Betzdorf |
| Independent monotonic witness, live certificate policy, combined rollback | `src/internal/witness/*_test.go`, real PostgreSQL `TestWitnessRejectsCombinedDatabaseAndLocalCheckpointRollback` |
| Optional PKCS#11 wrapping/rotation | `KMS_TEST_PKCS11_MODULE=<SoftHSM module> go test -race -tags pkcs11 ./src/internal/wrapping` |

The normal build intentionally has no PKCS#11 implementation. The tagged CI
acceptance uses a disposable SoftHSM token. Neither test establishes physical
HSM protection, SES acceptance or independent ETSI conformance. See
[REMOTE_QCI_UPGRADES](../docs/REMOTE_QCI_UPGRADES.md) for remaining software and
deployment boundaries.

# SDN services increment

`make sdn-services-demo` runs failure/ownership tests and two separate synthetic
KMS processes over independent mTLS roots with the actual TFS v7 driver contract.
It checks adapter authorization, lifecycle, inventory/sampling, lost activation
reply, restart replay and abort preserving a newer policy.
Validate `.local/sdn-services-node.json` with `tests/validate_sdn_yang.py`.
Go race tests cover deletion/reservation safety across local, ingest and relay
repositories, including propagation of relay voids.
See [SDN_SERVICES](../docs/SDN_SERVICES.md) for remaining conformance and deployment
gates; this test is not a full TFS cluster or hardware acceptance.
