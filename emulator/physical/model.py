"""Conditional optical and phase-BB84 model, not an adversarial security proof.

Large passes use expected counts and detector live fractions. The single-photon
yield used for budgeting is MODEL TRUTH, not a bound inferred from decoy data.
Thus budget_bits must never be described as composably secure key bits.
"""
from dataclasses import asdict, dataclass, replace
import math
import random

C = 299792458.0


def entropy(p):
    if p <= 0 or p >= 1:
        return 0.0
    return -p * math.log2(p) - (1-p) * math.log2(1-p)


@dataclass(frozen=True)
class BB84:
    symbol_hz: float = 2.25e9  # Includes SES 0.9 quantum-symbol duty factor.
    mus: tuple = (.63, .14, .001)  # Last intensity is NOT vacuum.
    probabilities: tuple = (.75, .1875, .0625)
    wavelength_nm: float = 1565.495864
    detector_efficiency: float = .6  # Assumption, needs SES receiver profile.
    visibility: float = .98
    optical_error: float = .015
    phase_sigma_rad: float = math.pi/50
    jitter_fwhm_ps: float = 50
    gate_ps: float = 80
    dead_time_ns: float = 80
    noise_hz_per_detector: float = 75  # Combined background + dark; not added twice.
    ec_efficiency: float = 1.5
    parameter_sample_per_basis: int = 1650000
    disclosed_fraction: float = .1  # Lab assumption, not an SES sample fraction.
    max_qber: float = .08  # Lab engineering gate, not an SES threshold.
    authentication_reserve_bits: int = 512  # Capacity charge only, no invented MAC.
    phase_start_values: int = 16

    def validate(self):
        values = asdict(self)
        for name, value in values.items():
            if isinstance(value, (int, float)) and (not math.isfinite(value) or value < 0):
                raise ValueError('Invalid BB84 parameter: ' + name)
        if not 1 <= self.symbol_hz <= 1e10 or len(self.mus) != 3 or len(self.probabilities) != 3:
            raise ValueError('Invalid source')
        if not all(math.isfinite(x) and 0 <= x <= 1 for x in self.probabilities) or abs(sum(self.probabilities)-1) > 1e-10:
            raise ValueError('Invalid intensity probabilities')
        if not all(math.isfinite(x) for x in self.mus) or not 0 <= self.mus[2] < self.mus[1] < self.mus[0] <= 2:
            raise ValueError('Invalid intensities')
        if not 0 < self.detector_efficiency <= 1 or not 0 <= self.visibility <= 1 or not 0 <= self.optical_error <= .5:
            raise ValueError('Invalid optics')
        if not 1 <= self.gate_ps <= 400 or not 0 <= self.max_qber < .5 or self.ec_efficiency < 1:
            raise ValueError('Invalid receiver or processing gate')
        if self.phase_start_values != 16 or type(self.parameter_sample_per_basis) is not int or self.parameter_sample_per_basis < 1 or not 0 < self.disclosed_fraction < 1:
            raise ValueError('This profile requires 16 discrete start phases and a positive sample')
        return self


def rates(profile, optical_eta, background_multiplier=1.0):
    """Four detector UMZI; one half central-slot and one half basis sifting.

    Dead time includes discarded side slots. Bright calibration illumination is
    excluded: its mission-specific blanking/recovery contract remains pending.
    """
    p = profile.validate()
    if not math.isfinite(optical_eta) or not 0 <= optical_eta <= 1 or not math.isfinite(background_multiplier) or background_multiplier < 0:
        raise ValueError('Invalid channel transmission or noise')
    eta = optical_eta * p.detector_efficiency
    sigma_ps = p.jitter_fwhm_ps / 2.354820045
    gate = 1.0 if sigma_ps == 0 else math.erf(p.gate_ps / (2*math.sqrt(2)*sigma_ps))
    gains = [-math.expm1(-mu*eta) for mu in p.mus]
    all_signal_hz = p.symbol_hz * sum(prob*q for prob, q in zip(p.probabilities, gains))
    noise = 4 * p.noise_hz_per_detector * background_multiplier
    live = 1 / (1 + (all_signal_hz+noise)/4*p.dead_time_ns*1e-9)
    accepted_noise = noise * min(1.0, p.gate_ps*1e-12*p.symbol_hz) * live
    error = (1-p.visibility*(1-2*p.optical_error)*math.exp(-p.phase_sigma_rad**2/2))/2
    rows = []
    for mu, prob, gain in zip(p.mus, p.probabilities, gains):
        signal = p.symbol_hz*prob*gain*.5*gate*live
        bg = accepted_noise*prob
        clicks = signal+bg
        rows.append(dict(mu=mu, probability=prob, detections_hz=clicks,
                         sifted_hz=clicks*.5, errors_hz=(signal*error+bg*.5)*.5,
                         qber=(signal*error+bg*.5)/clicks if clicks else .5))
    # This is explicitly an ideal-channel capacity proxy. It is NOT a vacuum
    # decoy formula (mu[2] != 0), nor a finite/discrete-phase security bound.
    mu, prob = p.mus[0], p.probabilities[0]
    single = p.symbol_hz*prob*mu*math.exp(-mu)*eta*.5*gate*live*.5
    q = rows[0]['qber']
    budget_hz = max(0, single*(1-entropy(error))-p.ec_efficiency*rows[0]['sifted_hz']*entropy(q))
    if q >= p.max_qber or optical_eta == 0:
        budget_hz = 0
    return dict(intensities=rows, qber=q, sifted_errors_hz=sum(x['errors_hz'] for x in rows), sifted_hz=sum(x['sifted_hz'] for x in rows),
                budget_hz=budget_hz, detector_live_fraction=live, gate_acceptance=gate,
                model_single_photon_hz=single, error_probability=error,
                detections_hz=sum(x['detections_hz'] for x in rows))


def fiber(length_km, attenuation_db_km=.2, insertion_db=3, refractive_index=1.468):
    if any(not math.isfinite(x) or x < 0 for x in (length_km, attenuation_db_km, insertion_db)) or refractive_index < 1:
        raise ValueError('Invalid fiber')
    loss = length_km*attenuation_db_km+insertion_db
    return dict(optical_eta=10**(-loss/10), optical_loss_db=loss,
                delay_s=length_km*1000*refractive_index/C)


def pulse_trial(profile, optical_eta, *, symbols=100000, seed=42):
    """Short, bounded Monte Carlo of pulse pairs; aggregate counts only.

    Samples phase start, intensity, basis, photons, UMZI central/side slot,
    detector port, timing jitter and persistent detector dead time. Double
    central clicks are discarded (a laboratory choice). No key export. Ambient
    counts are generated as a Poisson process. Reference frames/phase-lock
    electronics are not timestamp-emulated by this test.
    """
    p = profile.validate()
    if type(symbols) is not int or not 1 <= symbols <= 200000 or not 0 <= optical_eta <= 1:
        raise ValueError('Pulse trial exceeds the explicit 200,000-symbol limit')
    rng = random.Random(seed)
    busy = [-1.0]*4
    last_time = symbols/p.symbol_hz
    pending = []
    bits, bases = [], []
    counts = {name: 0 for name in ('emitted', 'central', 'sifted', 'errors', 'dead_time_rejected', 'double_discarded', 'side_slots')}
    for i in range(symbols):
        intensity = rng.choices(range(3), p.probabilities)[0]
        bit, basis = rng.randrange(2), rng.randrange(2)
        start_phase = rng.randrange(16)*math.pi/8
        relative = bit*math.pi+basis*math.pi/2
        bits.append(bit); bases.append(basis)
        # Poisson thinning gives the detected-photon population exactly for
        # this ideal coherent-state channel, without allocating lost photons.
        lam = p.mus[intensity]*optical_eta*p.detector_efficiency
        product, photons = 1.0, -1
        while product > math.exp(-lam):
            photons += 1; product *= rng.random()
        counts['emitted'] += 1
        for _ in range(max(0, photons)):
            receiver_basis = rng.randrange(2)
            central = rng.random() < .5
            delta = (start_phase+relative)-start_phase-receiver_basis*math.pi/2+rng.gauss(0, p.phase_sigma_rad)
            prob_zero = (1+p.visibility*(1-2*p.optical_error)*math.cos(delta))/2 if central else .5
            port = int(rng.random() >= prob_zero)
            jitter = rng.gauss(0, p.jitter_fwhm_ps/2.354820045)*1e-12
            slot_shift = 0 if central else rng.choice([-200e-12, 200e-12])
            pending.append((i/p.symbol_hz+slot_shift+jitter, receiver_basis*2+port, i,
                            central and abs(jitter) <= p.gate_ps*.5e-12, receiver_basis, port))
    if len(pending) > 500000:
        raise ValueError('Detected-event budget exceeded')
    for detector in range(4):
        if p.noise_hz_per_detector:
            t = rng.expovariate(p.noise_hz_per_detector)
            while t < last_time:
                i = min(symbols-1, round(t*p.symbol_hz))
                pending.append((t, detector, i, abs(t-i/p.symbol_hz) <= p.gate_ps*.5e-12, detector//2, detector%2))
                if len(pending) > 500000:
                    raise ValueError('Background event budget exceeded')
                t += rng.expovariate(p.noise_hz_per_detector)
    clicks = {}
    for t, detector, i, accepted, basis, bit in sorted(pending):
        if t < busy[detector]:
            counts['dead_time_rejected'] += 1
            continue
        busy[detector] = t+p.dead_time_ns*1e-9
        if accepted:
            clicks.setdefault(i, []).append((basis, bit)); counts['central'] += 1
        else:
            counts['side_slots'] += 1
    for i, values in clicks.items():
        if len(values) > 1:
            counts['double_discarded'] += 1
        elif values[0][0] == bases[i]:
            counts['sifted'] += 1; counts['errors'] += values[0][1] != bits[i]
    return dict(mode='bounded-pulse-Monte-Carlo', counts=counts,
                qber=counts['errors']/counts['sifted'] if counts['sifted'] else None,
                exported_keys=0, duration_s=last_time, phase_start_values=16,
                limitations=['no reference-frame electronics', 'double clicks discarded', 'no finite-key proof'])
