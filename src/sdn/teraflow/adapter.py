"""Explicit synthetic adapter for desired-state/telemetry acceptance only.

Vendor adapters must implement their agreed device control/observation contract.
This class cannot acknowledge catalog entries in 'adapter' or 'pending' mode.
"""
from datetime import datetime, timezone
import uuid


class SyntheticAdapter:
    def __init__(self, client):
        self.client = client

    def observe(self, link_id):
        state = self.client.state()
        matches = [link for link in state.get("links", []) if link["catalog"]["link_id"] == link_id]
        if len(matches) != 1 or matches[0]["catalog"]["mode"] != "synthetic":
            raise ValueError("Synthetic adapter requires an explicitly synthetic catalog entry")
        link = matches[0]
        desired = link["state"]
        enabled = desired["present"] and desired["enabled"]
        report = {"sequence": desired.get("report", {}).get("sequence", 0) + 1,
                  "desired_revision": desired["desired_revision"],
                  "observed_at": datetime.now(timezone.utc).isoformat(),
                  "status": "ACTIVE" if enabled else "OFF", "interface_status": "ENABLED" if enabled else "DISABLED",
                  "skr": 256 if enabled else 0, "eskr": 128 if enabled else 0, "qber": "1.000"}
        return self.client.apply({"command_id": str(uuid.uuid4()), "expected_revision": state["revision"],
                                  "association": link["catalog"]["association"],
                                  "service": {"operation": "link_report", "resource_id": link_id, "report": report}})
