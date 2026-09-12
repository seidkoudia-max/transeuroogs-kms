"""Explicit opt-in keeps other TeraFlow QKD devices on their existing driver."""
from device.service.driver_api._Driver import _Driver
from .QKDDriver import QKDDriver as TransEuroOGSDriver
from .client import PROFILE


class QKDDriver(_Driver):
    def __new__(cls, address, port=8443, **settings):
        profile = settings.get("profile")
        if profile == PROFILE:
            return TransEuroOGSDriver(address, port, **settings)
        if profile is not None:
            raise ValueError("Unsupported explicit QKD profile")
        from device.service.drivers.qkd.QKDDriver2 import QKDDriver as UpstreamDriver
        return UpstreamDriver(address, port, **settings)
