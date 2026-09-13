"""TransEuroOGS extension for the pinned TeraFlow v7 Device driver contract.

Install alongside other drivers and select it explicitly for this KMS profile.
Unsupported upstream physical-QKD provisioning must not report success.
"""
import json
import math
import threading
import time
from device.service.driver_api._Driver import _Driver
from .client import Client, ManagementError

ALLOCATION = "/transeuroogs/allocation"
STATE = "__transeuroogs_state__"
CHANGES = "__transeuroogs_changes__"
DEFAULT = ["__node__", "__capabilities__", "__apps__", "__interfaces__", "__links__", STATE]


class QKDDriver(_Driver):
    def __init__(self, address, port=8443, **settings):
        super().__init__("transeuroogs", address, port, **settings)
        required = {k: settings[k] for k in ("ca_file", "cert_file", "key_file", "server_identity")}
        self._subscriptions = {}
        self._monitor_lock = threading.Lock()
        self._reader_lock = threading.Lock()
        self._closed = threading.Event()
        self._cursor = 0
        self.client = Client(address, port, **required, timeout=settings.get("timeout", 5))

    def Connect(self):
        try:
            self.client.state()
            self._closed.clear()
            return True
        except ManagementError:
            return False

    def Disconnect(self):
        self._closed.set()
        return True  # Each request owns and closes its TLS connection.

    def GetInitialConfig(self):
        return self.GetConfig()

    def GetConfig(self, resource_keys=None):
        keys = DEFAULT if not resource_keys else resource_keys
        result = []
        try:
            node = self.client.node() if any(k != STATE for k in keys) else None
            for key in keys:
                if key == "__node__":
                    result.append((key, {k: v for k, v in node.items() if k not in ("qkd_applications", "qkd_interfaces", "qkd_links", "qkdn_capabilities")}))
                elif key == "__capabilities__":
                    result.append((key, node["qkdn_capabilities"]))
                elif key == "__apps__":
                    result.extend(("/app[" + a["app_id"] + "]", a) for a in node["qkd_applications"]["qkd_app"])
                elif key == "__interfaces__":
                    result.extend(("/interface[" + str(a["qkdi_id"]) + "]", a) for a in node["qkd_interfaces"].get("qkd_interface", []))
                elif key == "__links__":
                    result.extend(("/link[" + a["qkdl_id"] + "]", a) for a in node["qkd_links"].get("qkd_link", []))
                elif key == "__endpoints__":
                    for iface in node["qkd_interfaces"].get("qkd_interface", []):
                        number = str(iface["qkdi_id"])
                        result.append(("/endpoints/endpoint[qkd-" + number + "]", {"uuid": "qkd-" + number, "name": "QKD interface " + number, "type": "qkd"}))
                elif key == "__network_instances__":
                    # The local catalog does not establish physical network
                    # instance membership or authorize automatic path computation.
                    continue
                elif key == STATE:
                    result.append((key, self.client.state()))
                else:
                    result.append((key, NotImplementedError("Unsupported resource")))
            return result
        except (ManagementError, KeyError, TypeError):
            return [(key, ManagementError()) for key in keys]

    def SetConfig(self, resources):
        results = []
        for key, value in resources:
            if key != ALLOCATION:
                results.append(NotImplementedError("Unsupported resource"))
                continue
            try:
                command = json.loads(value) if isinstance(value, str) else value
                self.client.apply(command)
                results.append(True)
            except ManagementError as error:
                results.append(error)
            except (ValueError, KeyError, TypeError):
                results.append(ManagementError())
        return results

    def DeleteConfig(self, resources):
        return [NotImplementedError("Explicit replacement command required") for _ in resources]

    def SubscribeState(self, subscriptions):
        results = []
        with self._monitor_lock:
            for subscription in subscriptions:
                try:
                    key, duration, interval = subscription
                    if key not in (STATE, CHANGES) or not all(type(v) in (int, float) and math.isfinite(v) for v in (duration, interval)) or not 1 <= interval <= duration <= 86400:
                        raise ValueError()
                    self._subscriptions[key] = [time.monotonic() + duration, interval, 0]
                    results.append(True)
                except (ValueError, TypeError):
                    results.append(ValueError("Unsupported subscription or sampling bounds"))
        return results

    def UnsubscribeState(self, subscriptions):
        results = []
        with self._monitor_lock:
            for subscription in subscriptions:
                key = subscription[0] if isinstance(subscription, (tuple, list)) and len(subscription) == 3 else None
                if key not in (STATE, CHANGES):
                    results.append(ValueError("Unsupported subscription"))
                else:
                    self._subscriptions.pop(key, None)
                    results.append(True)
        return results

    def GetState(self, blocking=False, terminate=None):
        if not self._reader_lock.acquire(blocking=False):
            raise RuntimeError("Only one state consumer is supported per driver")
        try:
            while not self._closed.is_set() and not (terminate and terminate.is_set()):
                with self._monitor_lock:
                    now = time.monotonic()
                    self._subscriptions = {k: v for k, v in self._subscriptions.items() if now < v[0]}
                    due = [k for k, v in self._subscriptions.items() if v[2] <= now]
                    for key in due:
                        self._subscriptions[key][2] = now + self._subscriptions[key][1]
                    if not self._subscriptions and not blocking:
                        return
                for key in due:
                    try:
                        value = self.client.state() if key == STATE else self.client.changes(self._cursor)
                        if key == CHANGES:
                            # The endpoint retains history. This driver cursor is
                            # session-local; external consumers persist next_revision.
                            self._cursor = value["next_revision"]
                    except (ManagementError, KeyError, TypeError):
                        value = ManagementError()
                    with self._monitor_lock:
                        active = key in self._subscriptions and time.monotonic() < self._subscriptions[key][0]
                    if active and not self._closed.is_set() and not (terminate and terminate.is_set()):
                        yield time.time(), key, value
                if not blocking:
                    return
                self._closed.wait(0.1)
        finally:
            self._reader_lock.release()
