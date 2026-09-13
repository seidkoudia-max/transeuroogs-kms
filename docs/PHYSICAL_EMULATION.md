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

## Four independent channels and multiple passes

`multipass.json` extends the single-pass regression with three independently
constructed synthetic contact windows at 0, 6,000 and 12,000 seconds. Each
window has its own epoch, altitude and plane offset; the default altitudes are
600, 620 and 580 km. These are separate orbital test cases, **not three successive
revolutions of a single operational spacecraft**. QNETSIM computes range,
elevation, extinction and collection separately for each OGS throughout each
window. Only one downlink is illuminated at a time; each downlink nevertheless
has its own observations and independent pair pool. Fibre generation continues
between passes. The complete numerical experiment lasts 13,200 seconds.

All four channels have separate QBER and conditional SKR traces at the configured
2-second resolution. QBER is `null` outside contact, while key rate is zero.
The two downlinks are never collapsed into one QBER series. QBER is an expected
error fraction from the receiver signal/noise model, rather than an injected
random error percentage or a finite-sample security statistic.

For the downlinks, normalized irradiance is the product of two unit-mean Gamma
variables. With `v = sigma_R^2`, the shape parameters are the reciprocals of:

```
expm1(f * 0.49*v / (1 + 1.11*v^(6/5))^(7/6))
expm1(f * 0.51*v / (1 + 0.69*v^(6/5))^(5/6))
```

Here `v = zenith_rytov_variance / sin(elevation)^(11/6)`; the geometry factor is
limited below 5° and samples below the acquisition mask are not usable. The
configured factor `f` is a **phenomenological aperture-averaging input**, not
an aperture calibration inferred from the telescope diameter. Zero turbulence
gives unit irradiance. A Gaussian AR(1) copula, transformed through Gamma CDF
inverses, retains Gamma marginals and imposes a configurable temporal correlation.
Its coherence time and spectrum remain lab assumptions. This follows the
[Gamma–Gamma and slant-path Rytov model](https://www.janss.kr/archive/view_article_pubreader?pid=jass-37-1-11)
with explicitly supplied effective zenith variance. It does not simulate wave
propagation through phase screens, adaptive optics or an SES tracking servo.
Fading changes received signal relative to detector/sky noise; it does not
arbitrarily add phase errors to the phase-BB84 protocol. Receiver transmission
is physically bounded at one, with any clipping recorded.

Each fibre has separate correlated insertion-loss and classical-launch-power
processes. Classical power is lognormal with its configured mean. The Raman
receiver power follows the equal-attenuation approximation:

```
forward:  P * beta * bandwidth * L * exp(-alpha*L)
backward: P * beta * bandwidth * (1 - exp(-2*alpha*L)) / (2*alpha)
```

Length is in km, `alpha = attenuation_db_km * ln(10)/10`, and `beta` is per km
per nm. Power is converted to detector counts using photon energy and efficiency,
then the existing timing-gate/dead-time model applies. The fluctuating receiver
insertion loss attenuates signal and Raman photons together. See the
[primary Raman-noise derivation](https://www.nature.com/articles/s41598-018-21418-6).
Setting classical launch power or the Raman coefficient to zero removes that
contribution. Channel wavelengths, coexistence direction, power statistics,
filter bandwidth and Raman coefficients require site measurement; the defaults
are illustrative. Random streams are seeded separately for each link/component,
so changing one fibre does not perturb the other channels' random sequences.
Insertion loss is bounded below by zero; fluctuations cannot cancel the
configured fibre attenuation or create optical gain.

Raw pair capacity is tagged with its pass. Offline pairing requires both OGS
contributions from the **same** completed pass; a missing Helmos contact cannot
be silently repaired by unrelated material from another pass. Block accounting
also remains separate across passes. Expiry follows capacity through pairing
and end-to-end model establishment. Permit release deadlines are inherited from
the capacity blocks, with expired or delayed capacity burned. Each source has a
64-key disclosure allowance per pass, for at most 192 synthetic keys in the
default run. These are lab throttles, not estimates of full hardware throughput.

## Pointwise runtime and end-to-end verification

```sh
make physical-test PHYSICAL_PYTHON=/path/to/numerical/python
make physical-timeline-demo PHYSICAL_PYTHON=/path/to/numerical/python
```

Outputs are under `.local/physical/multipass/`. The repository's
`emulator/physical/report.html` is now a launcher for the generated report;
`report-template.html` contains the rendering template. The interactive report
has four QBER/SKR panels, pass selection, actual four-KMS inventory traces,
model pair-pool traces, and separately identified runtime evidence. It includes
the bounded completion period after the last model sample.

The runtime starts four empty KMSs and three separate synthetic paired-key
sources, then releases one common clock barrier after all management setup.
Source release **and expiry** use that clock, accelerated by 60 by default.
Every requested 60 simulated seconds, the coordinator reads all three source
inventories and all four KMS states over authenticated APIs. Actual observation
times and maximum sampling gaps are recorded: host scheduling and API latency
can delay a poll. No missing observations are interpolated or invented.

An exclusive lab coordinator checks non-consuming inventory on all three
transport segments, then asks JFK to create a bounded batch of independently
random application material. This uses the explicit `--synthetic-input-limit`
**stdin-only** count channel on a fresh, non-operational relay instance. It adds
no HTTP provisioning API. Only counts and acknowledgements cross that local
channel; key bytes remain inside the KMS. The session budget cannot be reset by
reopening persisted state, and failed provisioning or acknowledgements are not
retried. The preflight is an emulation coordination rule, not a new distributed
production reservation protocol.

Each pass requests 32 application keys. The normal run establishes 96 keys,
delivers 80 matching pairs to the two applications and leaves 16 buffered at
the observed completion point. Application requests use a separate demand
schedule from the DES token model; the actual application keys retain the
existing one-hour lab TTL, while source deadlines use the accelerated physical
clock. The graph labels these policies separately. Replay is checked after each
delivery. A bounded 600 simulated-second completion period accommodates relay
latency after the optical trace ends. Consuming calls are never blindly retried.

TeraFlow receives the same model-backed service telemetry and freshly observed
KMS counts during native execution. The two independent downlink observations
are carried, with their original model timestamps, in the reference service's
`latest_physical_links` metadata. They are **not** fabricated as one ETSI 015
QBER measurement on the offline paired-key service. The native service remains
a Context/WebUI reference record; ServiceService provisioning, a production
controller security profile and independent conformance evidence remain open.
After trace completion, KMS inventory continues refreshing, while physical
observations retain their final timestamps rather than claiming a new pass.

The native VM uses a 30× clock to accommodate controller RPC and amd64 emulation
latency. This changes wall-clock duration, not the physical model or simulated
expiry deadlines. The local default remains 60×; the actual factor appears in
each runtime report.
