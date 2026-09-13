# Helmos–Windhof physical and KMS emulation

The connected scenario is:

```
Lux4QCI                                         HellasQCI
JFK KMS — 25 km fibre — Windhof OGS      Helmos OGS — 30 km fibre — HellasQCI KMS
                          \              /
                           EAGLE-1 model
                       sequential optical contacts
                       followed by offline pairing
```

The runtime establishes a synthetic application key at JFK and transfers it
through Windhof and Helmos to HellasQCI. Each of the three hops consumes a
different paired link key through the existing authenticated ETSI 014 intake
and `qkd-jwe-v1` protected inter-KMS transport (standard JWE `dir`/`A256GCM`).
Satellite paired keys protect the middle hop; the model does not claim that
the end-to-end application key itself travelled optically aboard EAGLE-1.
JFK is the application master and HellasQCI the recipient in this direction.
Those roles do not make either OGS a mission-wide authentication authority.

## Physical and protocol models

The engine is the user's **QNETSIM standalone DES used by QUASAR**, with its
picosecond scheduler, WGS84/Skyfield geometry and Gaussian free-space collection
model. It is not the unrelated QuNetSim project. The separate dependency is
verified against [a source manifest](../emulator/physical/qnetsim.lock.json);
no substitute event engine is used when it is absent.

| Component | Implemented model | Calibration boundary |
| --- | --- | --- |
| Windhof OGS | QNETSIM's approximate 49.65° N, 5.95° E, 320 m ground position; 1 m receiving aperture | Surveyed position, telescope, coupling and detector parameters needed |
| Helmos OGS | QUASAR worksheet position, 2,340 m altitude, 2.3 m aperture and obscuration | Instrument settings are not an SES receiver specification |
| Satellite pass | Illustrative 600 km circular orbit aligned to Windhof then Helmos, Earth rotation, elevation mask, propagation delay and acquisition interval | This is not an EAGLE-1 ephemeris or planned mission pass |
| Optical channel | Gaussian annular aperture collection, averaged pointing jitter, elevation-dependent extinction and receiver loss | No wave-optics turbulence, adaptive-optics controller or measured weather distribution |
| Fibre QKD | User-specified 25 km and 30 km lengths, attenuation, insertion loss, propagation, photon statistics, detector noise/dead time | Generic phase-BB84 profiles; IDQ/other vendor hardware parameters remain inputs |
| Phase receiver | Relative-phase BB84, signal/weak/vacuum-like intensities, random bases, UMZI visibility, phase jitter, timing gate and four detectors | Reference-frame electronics, servo dynamics, afterpulsing and hardware efficiency mismatch are not emulated |
| Protocol processing | Sifting, block/sample gates, error/reconciliation and privacy-amplification **capacity budgets**, configurable delay | Actual mission error correction and privacy-amplification algorithms are not implemented |

[SES's published EAGLE-1 protocol presentation](https://www.ses.com/sites/default/files/2024-11/2024-11-11_The-Eagle-1_QKD_protocol.pdf)
provides the phase-encoded decoy-BB84 description, 0.63/0.14/0.001 photon
intensities, 16 discrete start phases, 2.25 Gsymbol/s effective quantum rate,
receiver timing/visibility limits and processing parameters. In particular,
0.001 is **not zero**; the model does not substitute a vacuum-decoy formula.
The presentation's minimum finite-size block is not treated as a prescribed
disclosure fraction. The 10% disclosure charge is a separate lab assumption.

Full passes use expected counts and a stationary-bin detector live fraction.
A bounded pulse-pair Monte Carlo separately samples basis/intensity/phase,
photon thinning, UMZI ports and side slots, timing, background and detector
dead time. It exports counts, not keys, and rejects oversized trials.

The reported SKR-like budget uses **model-truth single-photon yield**, not an
adversarial bound inferred from finite decoy observations. It is a conditional
engineering estimate, **not a composably secure key-rate calculation**.
Discrete-phase security, finite statistics, intensity uncertainty and the
complete SES security proof remain unvalidated. `security_proof_validated`
is false in every report and permit; the runtime rejects a contrary claim.
Key bytes used by the API tests come independently from Go `crypto/rand`.

## Buffers and key establishment

QNETSIM schedules distinct raw Windhof and raw Helmos satellite buffers, the
offline paired satellite pool, both fibre-link pools and the paired application
buffers at JFK/HellasQCI. Postprocessing emits capacity blocks. Offline pairing
waits until both contacts and the configured processing delay have completed.
End-to-end establishment consumes one paired key from each of the three link
pools. Capacity reservations, overflow, expiry, consumption and uncompleted
transfers are accounted for separately. Expired or spent tokens are never
returned to an available pool.

The default example uses 256-key link buffers, 64-key application buffers,
1,800-second token lifetimes and four-key application requests every 30 seconds
from simulation time 700 s. An early request can fail while the satellite
segment is unavailable. These are editable scenario assumptions, not deployment
sizing recommendations. Surplus output is discarded at a full buffer.

There are two complementary outputs:

* The reproducible DES report models a complete 20-minute supply/demand history.
* Real KMS acceptance starts four independent processes and three authenticated
  synthetic source processes. Each source receives a bounded, metadata-only
  permit derived from the physical buffers. It fills in disclosed batches of
  at most 16 keys, under an accelerated clock. Thirty-two real synthetic
  application keys traverse all three hops and match at JFK/HellasQCI.

The numerical buffer trace and the runtime test have different request
schedules. The report explicitly distinguishes them; numerical tokens are not
asserted to be signed KMS custody evidence. Runtime inventory samples and
telemetry receipts are saved separately without key bytes. The control input is
scheduled model playback, not a closed-loop quantum/hardware/controller twin.

A source claims its permit on durable storage **before** minting any material.
Any restart in that session refuses to regenerate it. Remaining source
capacity is burned if the process dies. KMS encrypted journals, incident holds
and delivery tombstones recover separately. A new lab session is explicit;
it is not recovery of a lost source's material. These disposable sources do
not implement production HA or a continuously renewable hardware pool.

## Run locally

Use a Python environment with [these numerical dependencies](../emulator/physical/requirements.txt),
then install the pinned files from the existing QNETSIM source directory:

```sh
python3 emulator/physical/bridge.py --source /path/to/QCompute/qnetsim
make physical-test PHYSICAL_PYTHON=/path/to/numerical/python
make physical-demo PHYSICAL_PYTHON=/path/to/numerical/python
```

On the current development Mac, the installed QNETSIM-compatible interpreter is
`/Users/seid.koudia/QCompute/.venv39/bin/python`. Set `GO` to the installed Go
toolchain when it is not on `PATH`. No changes are made to the user's QNETSIM
source or old simulation outputs. Its private source dependency is not
republished in this repository.

The output directory is `.local/physical/helmos-windhof/`. It contains
`report.json`, the three permits, `pulse-check.json`, `runtime-acceptance.json`,
captured `sdn-node.json` and an interactive `report.html`. The HTML is a
self-contained replay, with pass geometry, estimated rates, QBER, key-buffer
curves, aggregate accounting and parameter provenance. It contains no keys.

Faults in [scenario.json](../emulator/physical/scenario.json) can disable a
specific optical/fibre link, remove phase lock or increase background.
Supported link IDs are `eagle-windhof`, `eagle-helmos`, `fiber-windhof-jfk`
and `fiber-helmos-hellas`. For example:

```json
{"link":"eagle-helmos","kind":"cloud","start_s":0,"end_s":1200}
```

Full cloud cover at Helmos yields no paired satellite permit and no newly
established end-to-end keys. The runtime refuses to run the positive acceptance
case with inadequate budgets instead of silently seeding replacement keys.

## SDN and deployment

The physical adapter writes rates and observations only to explicitly synthetic
catalog entries, using the existing separately authorized mTLS adapter role.
Its durable outbox retains exact command IDs and revisions on uncertain
responses, locks concurrent writers and rejects time/scenario rewinds. A paired
satellite service has no single optical QBER; none is fabricated. An idle service
with stored paired keys can be reported as `PASSIVE`.

Application authorization is deliberately not tied to instantaneous optical
availability: already established keys remain usable after a pass or source
outage. Local pool holds, entitlement, expiry and single delivery still apply.
The native deployment uses TeraFlow NBI/Device commands with exact durable KMS
commit verification and fresh Device RPC observations. Its Context/WebUI record
is a reference service record, not a native ServiceService provisioning handler.

See [the deployment guide](../deploy/physical/README.md). The local emulation
pod contains four processes and a shared **test** CA. It models two QCI domains;
it does not provide production inter-domain host/CA isolation. Real SES/Vendor
interface acceptance, surveyed/calibrated optical inputs, mission ephemerides,
authoritative security proofs and operational deployment remain required.
