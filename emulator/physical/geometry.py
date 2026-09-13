"""An illustrative Kepler pass through the configured OGS directions.

Uses QNETSIM QUASAR's J2000 propagator and WGS84 transforms. Its historical
first-station key 'Matera' is translated immediately to the configured Windhof
site. No QUASAR orbit is misrepresented as an EAGLE-1 mission ephemeris.
"""
import datetime as dt
import math


def configure(qs, cfg):
    import numpy as np
    from skyfield.api import load, wgs84
    raw, v = qs.inputs()
    for row, site in zip((3, 9), cfg['stations']):
        for offset, field in enumerate(('latitude', 'longitude', 'altitude_m', 'diameter_m', 'obscuration_area')):
            v['C'+str(row+offset)] = site[field]
    v['C26'] = 6978.137  # 600 km over equatorial reference radius; lab assumption.
    v['C29'] = 0; v['C31'] = 0; v['C33'] = '2026-09-13T00:00:00'
    ts = load.timescale(builtin=True)
    epoch = dt.datetime(2026, 9, 13, tzinfo=dt.timezone.utc)
    first_overhead = 300.
    motion = math.sqrt(qs.MU/(v['C26']*1000)**3)

    def direction(site, t):
        observer = wgs84.latlon(site['latitude'], site['longitude'], elevation_m=site['altitude_m'])
        xyz = observer.at(ts.from_datetime(epoch+dt.timedelta(seconds=t))).position.m
        return xyz/np.linalg.norm(xyz)

    first = direction(cfg['stations'][0], first_overhead)
    transit = 350.
    for _ in range(12):
        second = direction(cfg['stations'][1], first_overhead+transit)
        transit = math.acos(float(np.clip(first@second, -1, 1)))/motion
    pole = np.cross(first, second); pole /= np.linalg.norm(pole)
    inc = math.acos(float(pole[2])); raan = math.atan2(float(pole[0]), -float(pole[1]))
    along_node = np.array([math.cos(raan), math.sin(raan), 0.])
    transverse = np.cross(pole, along_node)
    argument = math.atan2(float(first@transverse), float(first@along_node))-motion*first_overhead
    v['C30'] = math.degrees(inc); v['C27'] = math.degrees(raan)%360; v['C32'] = math.degrees(argument)%360
    return raw, v, first_overhead+transit/2


def orbit(qs, values, seconds):
    result = qs.orbit(values, seconds)
    return {key.replace('Matera_', 'Windhof_'): value for key, value in result.items()}
