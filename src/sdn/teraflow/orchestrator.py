"""Durable, bounded multi-domain coordination above TeraFlow Device drivers.

This project workflow is not an ETSI 021 wire implementation or a distributed
transaction. Each KMS commits independently. A partially activated service is
reported as such; resume replays exact commands, and abort only pauses delivery.
"""
import copy
import fcntl
import json
import os
from pathlib import Path
import tempfile
import uuid
from contextlib import contextmanager
from .QKDDriver import ALLOCATION, STATE


class Incomplete(RuntimeError):
    pass


class Orchestrator:
    def __init__(self, drivers, journal):
        self.drivers, self.journal = dict(drivers), Path(journal)

    @contextmanager
    def _lock(self):
        with open(str(self.journal) + ".lock", "a", opener=lambda p, f: os.open(p, f | os.O_NOFOLLOW, 0o600)) as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield

    def _save(self, job):
        raw = json.dumps(job, allow_nan=False, separators=(",", ":")).encode()
        if len(raw) > 1048576:
            raise ValueError("Workflow exceeds journal bound")
        fd, temporary = tempfile.mkstemp(prefix=".sdn-workflow-", dir=self.journal.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, self.journal)
            fd = os.open(self.journal.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _load(self):
        with open(self.journal, "rb", opener=lambda p, f: os.open(p, f | os.O_NOFOLLOW)) as stream:
            raw = stream.read(1048577)
        if len(raw) > 1048576:
            raise ValueError("Workflow exceeds journal bound")
        return json.loads(raw)

    def _observe(self, name, target):
        result = self.drivers[name].GetConfig([STATE])
        if len(result) != 1 or result[0][0] != STATE or not isinstance(result[0][1], dict):
            raise Incomplete("Domain observation unavailable: " + name)
        state = result[0][1]
        apps = [app for app in state["applications"] if app["association"] == target["association"]]
        if state["node_id"] != target["node_id"] or len(apps) != 1 or apps[0].get("pool", {}) != target["pool"]:
            raise Incomplete("Domain or immutable pool binding changed: " + name)
        return state, apps[0]

    def _new(self, desired):
        if not isinstance(desired, dict) or not 2 <= len(desired) <= 16 or set(desired) - self.drivers.keys():
            raise ValueError("Two to sixteen configured domains required")
        # Validate/observe every participant before persisting or sending intent.
        revisions, apps = {}, {}
        for name, target in desired.items():
            if (not isinstance(target, dict) or set(target) - {"node_id", "pool", "association", "rule", "routes", "service"}
                    or not {"node_id", "pool", "association", "rule"} <= target.keys()
                    or not isinstance(target["rule"], dict) or type(target["rule"].get("paused")) is not bool):
                raise ValueError("Explicit domain, pool, association and complete rule required")
            state, app = self._observe(name, target)
            revisions[name], apps[name] = state["revision"], app
            service = target.get("service")
            if service is not None and (service.get("operation") not in ("application_create", "application_update") or service.get("resource_id") != app["app_id"]):
                raise ValueError("Only observed application registration/update can be provisioned")
            if service is None and app.get("service") is not None and not app["service"]["registered"]:
                raise ValueError("Managed application needs an explicit registration request")
        actions = []
        for phase in ("pause", "provision", "configure", "activate"):
            for name, target in desired.items():
                if phase == "provision" and "service" not in target:
                    continue
                command = {"command_id": str(uuid.uuid4()), "expected_revision": revisions[name], "association": target["association"]}
                if phase == "provision":
                    command["service"] = target["service"]
                else:
                    rule = copy.deepcopy(apps[name]["rule"] if phase == "pause" else target["rule"])
                    if phase != "activate":
                        rule["paused"] = True
                    command["rule"] = rule
                    if phase == "configure" and "routes" in target:
                        command["routes"] = target["routes"]
                actions.append({"domain": name, "phase": phase, "command": command})
                revisions[name] += 1
        return {"profile": "transeuroogs-multidomain-v1", "desired": copy.deepcopy(desired), "actions": actions,
                "completed": 0, "status": "pending", "abort_actions": {}, "paused_domains": []}

    def run(self, desired):
        with self._lock():
            job = self._load() if self.journal.exists() else self._new(desired)
            if job["desired"] != desired:
                raise ValueError("Existing journal belongs to a different intent")
            if job["status"] in ("aborting", "aborted"):
                raise Incomplete("Aborted workflow cannot resume activation")
            self._save(job)  # All command identities/intents durable before calls.
            while job["completed"] < len(job["actions"]):
                action = job["actions"][job["completed"]]
                name = action["domain"]
                self._observe(name, desired[name])
                result = self.drivers[name].SetConfig([(ALLOCATION, action["command"])])
                if result != [True]:
                    job["status"] = "partial_activation" if action["phase"] == "activate" else "incomplete"
                    self._save(job)
                    raise Incomplete("Unresolved " + action["phase"] + " in " + name + "; resume exact intent or abort")
                job["completed"] += 1
                job["status"] = "pending"
                self._save(job)
            job["status"] = "complete"
            self._save(job)
            return job

    def abort(self):
        # A successful CAS pause supersedes any delayed original command. It
        # preserves the currently observed policy, never restores an old policy,
        # returns keys to a pool, deletes resources, or relaxes an incident hold.
        with self._lock():
            job = self._load()
            job["status"] = "aborting"
            self._save(job)
            failed = []
            for name, target in job["desired"].items():
                if name in job["paused_domains"]:
                    continue
                try:
                    state, app = self._observe(name, target)
                    if name not in job["abort_actions"]:
                        rule = copy.deepcopy(app["rule"]); rule["paused"] = True
                        job["abort_actions"][name] = {"command_id": str(uuid.uuid4()), "expected_revision": state["revision"],
                                                      "association": target["association"], "rule": rule}
                        self._save(job)
                    if self.drivers[name].SetConfig([(ALLOCATION, job["abort_actions"][name])]) != [True]:
                        raise Incomplete("Pause outcome unresolved")
                    job["paused_domains"].append(name)
                    self._save(job)
                except Incomplete:
                    failed.append(name)
            if failed:
                raise Incomplete("Abort remains incomplete in: " + ", ".join(failed))
            job["status"] = "aborted"
            self._save(job)
            return job
