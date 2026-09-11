# Data model

The baseline stores opaque 256-bit values. It does not split, combine, derive,
relay or transform keys. IDs are canonical lowercase UUIDv4 strings generated
from `crypto/rand`; duplicate IDs are rejected even after consumption.

`Key` contains ID, material, source label, ordered master/slave SAE pair,
creation time and expiry. Input byte slices are copied on ingestion. Material
is excluded from generic JSON and string formatting. `Metadata` has no bytes.

Each stored ID has two independent delivery records:

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
remain for the process lifetime. A new source record cannot overwrite one.

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
repository implementation. Transfer states and durable peer transaction IDs
are reserved for the ETSI 020 milestone, not emulated by local consumption.
