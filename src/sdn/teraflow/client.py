"""Material-free management client. Standard TLS; no cryptographic extensions."""
import http.client
import json
import ssl
import uuid

NODE = "/restconf/data/etsi-qkd-sdn-node:qkd_node"
STATE = "/management/v1/state"
COMMAND = "/management/v1/commands"
PROFILE = "transeuroogs-allocation-v1"


class ManagementError(Exception):
    def __init__(self, status=0):
        self.status = status
        super().__init__("KMS management request failed" + (" (HTTP %d)" % status if status else ""))


class Client:
    def __init__(self, host, port, *, ca_file, cert_file, key_file, server_identity, timeout=5):
        if not isinstance(host, str) or any(c in host for c in "/@?#\\\r\n") or not host:
            raise ValueError("Invalid KMS host")
        if not isinstance(server_identity, str) or not server_identity.startswith("urn:"):
            raise ValueError("Expected a configured server URI identity")
        if not 1 <= int(port) <= 65535 or not 0 < float(timeout) <= 30:
            raise ValueError("Invalid connection bounds")
        self.host, self.port, self.identity, self.timeout = host, int(port), server_identity, float(timeout)
        self.context = ssl.create_default_context(cafile=ca_file)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.load_cert_chain(certfile=cert_file, keyfile=key_file)

    def request(self, method, path, payload=None):
        if (method, path) not in {("GET", NODE), ("GET", STATE), ("POST", COMMAND), ("GET", "/management/v1/capabilities")}:
            raise ValueError("Unsupported management resource")
        encoded = None if payload is None else json.dumps(payload, allow_nan=False, separators=(",", ":")).encode()
        if encoded is not None and len(encoded) > 16384:
            raise ValueError("Command too large")
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.context)
        try:
            connection.connect()  # Chain, validity, EKU and DNS/IP checks first.
            uris = [v for k, v in connection.sock.getpeercert().get("subjectAltName", ()) if k == "URI"]
            if uris != [self.identity]:
                raise ManagementError()
            connection.request(method, path, body=encoded, headers={"Accept": "application/yang-data+json" if path == NODE else "application/json", "Content-Type": "application/json"})
            response = connection.getresponse()
            # No redirects and no automatic mutation retry. A timeout after POST
            # has an uncertain outcome; only the identical command may be retried.
            if response.status != 200:
                raise ManagementError(response.status)
            content_type = response.getheader("Content-Type", "").split(";", 1)[0]
            if content_type != ("application/yang-data+json" if path == NODE else "application/json"):
                raise ManagementError()
            body = response.read(131073)
            if len(body) > 131072:
                raise ManagementError()
            return json.loads(body)
        except (OSError, ValueError, http.client.HTTPException):
            raise ManagementError() from None
        finally:
            connection.close()

    def state(self):
        result = self.request("GET", STATE)
        if result.get("profile") != PROFILE or not isinstance(result.get("revision"), int) or not isinstance(result.get("applications"), list):
            raise ManagementError()
        return result

    def node(self):
        result = self.request("GET", NODE)
        return result["etsi-qkd-sdn-node:qkd_node"]

    def apply(self, command):
        if not isinstance(command, dict) or str(uuid.UUID(command["command_id"])) != command["command_id"]:
            raise ValueError("A stable command UUID is required")
        result = self.request("POST", COMMAND, command)
        if result.get("command") != command or result.get("revision") != command["expected_revision"] + 1:
            raise ManagementError()
        return result
