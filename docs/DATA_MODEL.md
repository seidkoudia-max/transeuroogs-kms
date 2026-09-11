# Data model

The baseline stores opaque 256-bit values. It does not split, combine, derive,
or transform keys. Network mode forwards unchanged keys across trusted relays. IDs are canonical lowercase UUIDv4 strings generated
from `crypto/rand`; duplicate IDs are rejected even after consumption.

`Key` contains ID, material, source label, ordered master/slave SAE pair,
creation time and expiry. Input byte slices are copied on ingestion. Material
is excluded from generic JSON and string formatting. `Metadata` has no bytes.

In the original local memory fixture, each stored ID has two independent delivery records:

| Recipient | Initial state | Delivery transition |
| --- | --- | --- |
| Master | AVAILABLE | AVAILABLE → RESERVED → CONSUMED |
| Slave | RESERVED (waiting for master) | RESERVED → AVAILABLE on master consumption; AVAILABLE → CONSUMED by ID |

The slave copy represents the corresponding authorized application delivery;
it is never offered for a new master allocation. CONSUMED is terminal for that
recipient. No API returns a consumed delivery to AVAILABLE.

Any unconsumed delivery becomes EXPIRED at `now >= expires_at`. Invalidation
moves unconsumed deliveries to INVALID. Both operations discard the relevant
material. CONSUMED, INVALID and EXPIRED stay terminal. Identity tombstones
remain for the memory process lifetime, or durably in network mode. A new source record cannot overwrite one.

`Reservation` contains an opaque UUID token and IDs. The repository retains
the ordered association and exact batch behind the token; a caller cannot
change membership. Only the matching master/slave pair can consume it. A token
can succeed once. Unknown, expired or invalid reservations cannot deliver.

By-ID consumption checks every ID, association, availability and expiry before
changing any requested delivery. Duplicated IDs or any inaccessible member
reject the whole batch. Selection order is insertion order, avoiding map-order
dependence in demonstrations.

Persistence contract: StoreKey, ReserveKeys, ConsumeReservation, ConsumePeerKeys,
InvalidateKey, Metadata, Inventory. Transaction atomicity belongs to the
repository implementation.

The network repository adds source/relay/target roles, the immutable ID/pair/
material-extension digest, incoming peer, candidate routes, selected peer,
persisted send intent, readiness, per-local-recipient consumption, expiry and
void propagation. `relayed` ACKs travel from the target back to the origin;
only then may the origin reserve its local delivery. Relay nodes clear material
after downstream acknowledgement. No intermediate has an SAE delivery role.

Persistent ACK jobs are separate from key records so results can be retried
without retaining key material. Unknown void IDs receive terminal tombstones.
Repeated input must match the original binding and cannot reset delivery or
expiry. Snapshots commit before network side effects and SAE responses.
Read [ETSI020_PROFILE](ETSI020_PROFILE.md) for recovery and failover rules.

## Segmented upstream ingestion

`ingest.Repository` provides a separate durable implementation of `core.Repository`.
Its journal binds the upstream URL/identity, gateway SAE pair, local application
pair, role and capacity. Key IDs are preserved unchanged, with one configured
application pair per gateway pair. Other key formats and ID translation remain
unsupported rather than silently transformed.

Request records retain intent, attempted count, IDs when known, start/expiry and
pending/stored/consumed/uncertain outcome. Key records retain local state and
material only for unconsumed master reservations. Slave retrieval commits
consumption directly before returning bytes. The opposite endpoint's rights are
not represented as locally deliverable copies. Pending requests on restart
become uncertain; known IDs remain invalid and cannot be retried. Each national
endpoint maintains its own recipient state, trusting the provider for paired-key
establishment. There is no secondary terrestrial relay on import.

Capacity counts attempted slots, including unknown-ID master failures. Retention
is local; common absolute expiry and cross-site revocation remain unsupported.
See [EAGLE1_INTEGRATION](EAGLE1_INTEGRATION.md) for the service contract and limits.

## PostgreSQL and application metadata

The optional PostgreSQL backend persists each repository's complete lifecycle
snapshot as authenticated ciphertext. `kms_meta.state` exposes only allowlisted
IDs, associations, states and timestamps. `kms_secret.state` contains the encrypted
snapshot; an observer role cannot access it. Generation/version, public metadata
and a separately persisted checkpoint bind each committed state. Audit intent/
result and transition records contain no key bytes or arbitrary request bodies.

The reference application's SQLite ledger stores session ID, unique KID when
known, expiry, and uncertain/confirmed state. It commits before key retrieval;
unknown-ID allocation attempts remain terminal. Keys exist only in transient
application/TLS memory. See [OPERATIONS](OPERATIONS.md) and
[APPLICATION_INTEGRATION](APPLICATION_INTEGRATION.md).
