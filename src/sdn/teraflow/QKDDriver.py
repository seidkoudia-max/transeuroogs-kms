"""TransEuroOGS extension for the pinned TeraFlow v7 Device driver contract.

Install alongside other drivers and select it explicitly for this KMS profile.
Unsupported upstream physical-QKD provisioning must not report success.
"""
import json
from device.service.driver_api._Driver import _Driver
from .client import Client, ManagementError

ALLOCATION = "/transeuroogs/allocation"
STATE = "__transeuroogs_state__"
DEFAULT = ["__node__", "__capabilities__", "__apps__", "__interfaces__", "__links__"]


class QKDDriver(_Driver):
    def __init__(self, address, port=8443, **settings):
        super().__init__("transeuroogs", address, port, **settings)
        required = {k: settings[k] for k in ("ca_file", "cert_file", "key_file", "server_identity")}
        self.client = Client(address, port, **required, timeout=settings.get("timeout", 5))

    def Connect(self):
        try:
            self.client.state()
            return True
        except ManagementError:
            return False

    def Disconnect(self):
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
                elif key in ("__endpoints__", "__interfaces__", "__links__", "__network_instances__"):
                    # This KMS has no physical attachment observations. Do not
                    # synthesize ports or quantum links for TFS path computation.
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
            except (ManagementError, ValueError, KeyError, TypeError):
                results.append(ManagementError())
        return results

    def DeleteConfig(self, resources):
        return [NotImplementedError("Explicit replacement command required") for _ in resources]

    def SubscribeState(self, subscriptions):
        return [NotImplementedError("Use scoped snapshot polling") for _ in subscriptions]

    def UnsubscribeState(self, subscriptions):
        return [NotImplementedError("No subscriptions exist") for _ in subscriptions]

    def GetState(self, blocking=False, terminate=None):
        raise NotImplementedError("Use GetConfig for scoped snapshot polling")
