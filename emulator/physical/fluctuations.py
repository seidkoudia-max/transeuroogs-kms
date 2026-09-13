"""Seeded channel physics, independent per link; never randomize QBER directly.

Gamma–Gamma parameters use the plane-wave Rytov approximation. The configured
zenith Rytov variance and aperture variance multiplier need site calibration.
Raman equations assume equal classical/quantum fibre attenuation. References
and temporal/coherence assumptions are recorded in PHYSICAL_EMULATION.md.
"""
import hashlib
import math
import random

PLANCK = 6.62607015e-34
C = 299792458.0


def stream(seed, label):
    return random.Random(int.from_bytes(hashlib.sha256(f'{seed}:{label}'.encode()).digest(), 'big'))


class CorrelatedNormal:
    """Stationary unit Gaussian AR(1); correlation is exp(-delta/tau)."""
    def __init__(self, rng, tau):
        self.rng, self.tau, self.value = rng, tau, rng.gauss(0, 1)
        self.first = True

    def next(self, delta):
        if self.first:
            self.first = False
        else:
            rho = math.exp(-delta/self.tau) if self.tau else 0
            self.value = rho*self.value + math.sqrt(1-rho*rho)*self.rng.gauss(0, 1)
        return self.value


def gamma_parameters(rytov_variance, aperture_factor=1):
    if not math.isfinite(rytov_variance) or rytov_variance < 0 or not 0 < aperture_factor <= 1:
        raise ValueError('Invalid Gamma–Gamma variance')
    if rytov_variance == 0:
        return None, None
    v = rytov_variance
    # sigma_R^(12/5) = (sigma_R^2)^(6/5), not v^(12/5).
    large = .49*v/(1+1.11*v**1.2)**(7/6)
    small = .51*v/(1+.69*v**1.2)**(5/6)
    return 1/math.expm1(aperture_factor*large), 1/math.expm1(aperture_factor*small)


def gamma_draw(rng, alpha, beta):
    return 1. if alpha is None else rng.gammavariate(alpha, 1/alpha)*rng.gammavariate(beta, 1/beta)


def raman_noise(length_km, attenuation_db_km, power_w, coefficient_per_km_nm,
                filter_nm, wavelength_nm, efficiency, direction='forward'):
    values = (length_km, attenuation_db_km, power_w, coefficient_per_km_nm, filter_nm, wavelength_nm, efficiency)
    if any(not math.isfinite(x) or x < 0 for x in values) or wavelength_nm == 0 or efficiency > 1 or direction not in ('forward','backward'):
        raise ValueError('Invalid Raman channel')
    alpha = attenuation_db_km*math.log(10)/10
    effective = length_km*math.exp(-alpha*length_km) if direction == 'forward' else (-math.expm1(-2*alpha*length_km)/(2*alpha) if alpha else length_km)
    watts = power_w*coefficient_per_km_nm*filter_nm*effective
    # Total receiver count rate, before timing gating and detector dead time.
    return watts/(PLANCK*C/(wavelength_nm*1e-9))*efficiency


class Channels:
    def __init__(self, cfg):
        self.cfg = cfg
        self.series = {}

    def normal(self, label, tau, delta):
        if label not in self.series:
            self.series[label] = CorrelatedNormal(stream(self.cfg['seed'], label), tau)
        return self.series[label].next(delta)

    def fiber(self, link, profile, delta):
        f = link.get('fluctuations', {})
        base_loss = link['length_km']*link['attenuation_db_km']+link['insertion_db']
        loss_shift = f.get('loss_sigma_db', 0)*self.normal(link['id']+':loss', f.get('correlation_s', 0), delta)
        loss = max(link['length_km']*link['attenuation_db_km'], base_loss+loss_shift)
        sigma = f.get('power_log_sigma', 0)
        power = f.get('classical_power_w', 0)*math.exp(sigma*self.normal(link['id']+':raman', f.get('correlation_s', 0), delta)-sigma*sigma/2)
        # Random excess loss represents a receiver-side coupling/insertion loss,
        # so it attenuates Raman photons as well as the quantum signal.
        noise = raman_noise(link['length_km'], link['attenuation_db_km'], power,
                            f.get('raman_coefficient_per_km_nm', 0), f.get('filter_nm', .1),
                            profile.wavelength_nm, profile.detector_efficiency, f.get('direction', 'forward'))
        noise *= 10**(-(loss-link['length_km']*link['attenuation_db_km'])/10)
        return dict(optical_eta=10**(-loss/10), loss_delta_db=loss-base_loss,
                    raman_noise_hz=noise, classical_power_w=power)

    def space(self, station, elevation, pass_id, delta):
        f = station.get('turbulence', {})
        if elevation is None or elevation <= 0:
            return dict(irradiance=1., rytov_variance=0., gamma_alpha=None, gamma_beta=None, sky_noise_hz=0.)
        air = 1/math.sin(math.radians(max(5, elevation)))
        variance = f.get('zenith_rytov_variance', 0)*air**(11/6)
        alpha, beta = gamma_parameters(variance, f.get('aperture_variance_factor', 1))
        value = 1.
        if alpha is not None:
            from scipy.special import ndtr
            from scipy.stats import gamma
            # A Gaussian copula retains Gamma marginals while imposing an
            # explicit temporal model. It is not a measured turbulence spectrum.
            for shape, component in ((alpha,'large'), (beta,'small')):
                z = self.normal(station['name']+':'+pass_id+':'+component, f.get('correlation_s', 0), delta)
                u = min(1-1e-12, max(1e-12, float(ndtr(z))))
                value *= float(gamma.ppf(u, shape, scale=1/shape))
        return dict(irradiance=value, rytov_variance=variance, gamma_alpha=alpha, gamma_beta=beta,
                    sky_noise_hz=4*f.get('zenith_sky_noise_hz_per_detector', 0)*air)


def validate(cfg):
    for site in cfg['stations']:
        f = site.get('turbulence', {})
        for key, low, high in [('zenith_rytov_variance',0,5), ('aperture_variance_factor',1e-4,1),
                               ('correlation_s',0,600), ('zenith_sky_noise_hz_per_detector',0,1e8)]:
            if key in f and (not math.isfinite(f[key]) or not low <= f[key] <= high): raise ValueError('Invalid turbulence '+key)
    for link in cfg['terrestrial']:
        f = link.get('fluctuations', {})
        for key, low, high in [('loss_sigma_db',0,10), ('power_log_sigma',0,2), ('correlation_s',0,3600),
                               ('classical_power_w',0,1), ('raman_coefficient_per_km_nm',0,1e-5), ('filter_nm',.001,10)]:
            if key in f and (not math.isfinite(f[key]) or not low <= f[key] <= high): raise ValueError('Invalid fibre fluctuation '+key)
        if f.get('direction','forward') not in ('forward','backward'): raise ValueError('Invalid Raman direction')
