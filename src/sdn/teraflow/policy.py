"""One-domain policy reconciliation on top of a TeraFlow Device driver.

The caller supplies approved desired policy. This component uses KMS metadata
for reconciliation; it neither schedules QKD hardware nor coordinates secrets.
"""
import json
import os
import pathlib
import uuid
from .QKDDriver import ALLOCATION, STATE


class Reconciler:
    def __init__(self, driver, outbox):
        self.driver, self.outbox = driver, pathlib.Path(outbox)

    def reconcile(self, desired):
        observed = self.driver.GetConfig([STATE])
        if len(observed) != 1 or observed[0][0] != STATE or not isinstance(observed[0][1], dict):
            raise RuntimeError("KMS observation unavailable")
        state = observed[0][1]
        # An outbox filename belongs to exactly one node and pending operation.
        # Never overwrite or replace an uncertain command with a newer intent.
        if self.outbox.exists():
            envelope = json.loads(self.outbox.read_text())
            if envelope["node_id"] != state["node_id"] or envelope["desired"] != desired:
                raise RuntimeError("Resolve pending operation before changing intent")
        else:
            if not isinstance(desired, dict) or set(desired) - {"association", "rule", "routes"} or "association" not in desired or "rule" not in desired:
                raise ValueError("Explicit association and complete rule required")
            matches = [a for a in state["applications"] if a["association"] == desired["association"]]
            if len(matches) != 1:
                raise ValueError("Association outside observed scope")
            app = matches[0]
            if app["rule"] == desired["rule"] and ("routes" not in desired or app["routes"] == desired["routes"]):
                return {"changed": False, "revision": state["revision"], "eligible": app["counts"]["eligible"]}
            command = dict(desired, command_id=str(uuid.uuid4()), expected_revision=state["revision"])
            envelope = {"node_id": state["node_id"], "desired": desired, "command": command}
            # Exclusive creation also prevents two workers publishing different
            # commands to the same outbox. Contents contain no key material.
            with open(self.outbox, "x", opener=lambda p, flags: os.open(p, flags, 0o600)) as f:
                f.write(json.dumps(envelope, allow_nan=False))
                f.flush(); os.fsync(f.fileno())
            self._sync_directory()
        results = self.driver.SetConfig([(ALLOCATION, envelope["command"])])
        if results != [True]:
            raise RuntimeError("Policy outcome unresolved; retain exact outbox for retry")
        # The command result is durable at the KMS. A crash before this unlink
        # merely repeats the identical command and receives the original result.
        self.outbox.unlink()
        self._sync_directory()
        return {"changed": True, "revision": envelope["command"]["expected_revision"] + 1}

    def _sync_directory(self):
        fd = os.open(str(self.outbox.parent), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
