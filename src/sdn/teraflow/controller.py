"""Controller-backed workflow adapter; a TFS response alone is not a KMS commit."""
import http.client
import json
import uuid
from .client import ManagementError, canonical_command
from .QKDDriver import ALLOCATION, STATE


class NBI:
    def __init__(self, host="nbiservice", port=8080):
        if not host or any(c in host for c in "/@?#\\\r\n") or not 1 <= int(port) <= 65535:
            raise ValueError("Invalid internal controller endpoint")
        self.host, self.port = host, int(port)

    def request(self, method, path, body=None):
        # This upstream lab NBI is internal plaintext HTTP. Network policy and
        # loopback forwarding bound access; production requires its own auth/TLS.
        if not (method == "POST" and path == "/devices"):
            tail = path.removeprefix("/device/")
            if method not in ("GET", "PUT") or not path.startswith("/device/") or str(uuid.UUID(tail)) != tail:
                raise ValueError("Unsupported NBI operation")
        encoded = None if body is None else json.dumps(body, allow_nan=False)
        if encoded and len(encoded.encode()) > 131072:
            raise ValueError("NBI body exceeds bound")
        conn = http.client.HTTPConnection(self.host, self.port, timeout=30)
        try:
            conn.request(method, "/tfs-api" + path, body=encoded, headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            raw = response.read(1048577)
            if not 200 <= response.status < 300 or len(raw) > 1048576:
                raise ManagementError(response.status)
            return json.loads(raw)
        finally:
            conn.close()


class ControllerAdapter:
    def __init__(self, node_id, observer, snapshot, *, actor, nbi=None):
        self.node_id, self.observer, self.snapshot, self.actor = node_id, observer, snapshot, actor
        self.nbi = nbi or NBI()

    def GetConfig(self, keys):
        if keys != [STATE]:
            return [(key, NotImplementedError("Only scoped state is available")) for key in keys]
        try:
            state = self.snapshot(self.node_id)  # Actual TFS Device.GetInitialConfig.
            if state["node_id"] != self.node_id:
                raise ManagementError()
            return [(STATE, state)]
        except Exception:
            return [(STATE, ManagementError())]

    def SetConfig(self, resources):
        if len(resources) != 1 or resources[0][0] != ALLOCATION:
            return [NotImplementedError("Explicit KMS command required") for _ in resources]
        command = resources[0][1]
        try:
            request = {"device_id": {"device_uuid": {"uuid": self.node_id}}, "device_config": {"config_rules": [
                {"action": "CONFIGACTION_SET", "custom": {"resource_key": ALLOCATION, "resource_value": json.dumps(command, allow_nan=False)}}]}}
            self.nbi.request("PUT", "/device/" + self.node_id, request)
            page = self.observer.changes(command["expected_revision"])
            for commit in page["changes"]:
                if (commit["actor"] == self.actor and commit["revision"] == command["expected_revision"] + 1
                        and canonical_command(commit["command"]) == canonical_command(command)):
                    return [True]
            raise ManagementError()
        except Exception:
            # A timeout, dropped response, stale TFS cache or wrong commit is an
            # unresolved outcome. The caller retains the identical durable intent.
            return [ManagementError()]
