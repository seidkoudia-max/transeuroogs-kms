"""Synthetic metadata acceptance; never persist or print key material."""
import datetime
import json
import subprocess
import uuid


class MetadataLab:
    def __init__(self, binary, directory, require):
        self.binary, self.directory, self.require = binary, directory, require
        self.trust = []
        self.audience = "urn:transeuroogs:sae:unknown-sae"

    def configure(self, cfg, site):
        private = self.directory / (site + "-metadata.key.pem")
        public = self.directory / (site + "-metadata.pub.pem")
        subprocess.run([str(self.binary), "keygen", "--private", str(private),
                        "--public", str(public)], check=True, capture_output=True)
        now = datetime.datetime.now(datetime.timezone.utc)
        cfg["metadata"] = {
            "domain": site.upper(), "issuer": "urn:transeuroogs:kme:" + site,
            "namespace": "synthetic-eagle-gateway-pair", "credential_id": site + "-metadata-v1",
            "signing_key_file": str(private), "max_events": 4096,
            "clock_uncertainty_ms": 0,
            "readers": {self.audience: cfg["associations"]},
        }
        self.trust.append({
            "issuer": cfg["metadata"]["issuer"], "domain": site.upper(),
            "namespace": cfg["metadata"]["namespace"], "credential_id": site + "-metadata-v1",
            "public_key_file": str(public), "pairs": cfg["associations"],
            "valid_from": (now - datetime.timedelta(days=1)).isoformat(),
            "valid_until": (now + datetime.timedelta(days=1)).isoformat(), "revoked": False,
        })

    def verify(self, local, pki, context, last_id):
        pages = []
        for site in ("lu", "gr"):
            code, view = local(site, "/metadata/v1/keys/" + last_id)
            self.require(code == 200 and view["view"]["generation_time"] is None,
                         "Provider generation time was invented")
            self.require(view["view"]["key"]["key_id"] == last_id
                         and "upstream" not in view["view"] and "next_peer" not in view["view"],
                         "Incorrect or excessive application metadata")
            code, _ = local(site, "/metadata/v1/events")
            self.require(code == 403, "Application obtained investigator history")
            auditor = context(pki[site], pki[site], "unknown-sae")
            after, through = 0, 0
            for _ in range(1000):
                path = f"/metadata/v1/events?after={after}&through={through}&limit=8"
                code, page = local(site, path, ctx=auditor)
                self.require(code == 200, "Metadata export failed")
                pages.append(page)
                through = page["page"]["watermark"]
                after = page["page"]["next"]
                if page["page"]["page_complete"]:
                    break
            else:
                raise RuntimeError("Metadata export did not terminate")
        events = [p["event"] for page in pages for p in page["page"]["events"]]
        lu = [e for e in events if e["issuer"].endswith(":lu") and "record" in e]
        first = next(e for e in lu if "custody_started" in e["actions"])
        final = next(e for e in lu if "master_CONSUMED" in e["actions"]
                     and e["record"]["key"] == first["record"]["key"])
        query = {"incident_id": str(uuid.uuid4()), "subject": first["issuer"],
                 "kind": "material_exposure", "start": first["recorded_at"],
                 "end": final["recorded_at"], "clock_uncertainty_ms": 0, "limit": 128}
        auditor = context(pki["lu"], pki["lu"], "unknown-sae")
        code, report = local("lu", "/metadata/v1/trace", query, ctx=auditor)
        self.require(code == 200 and any(f["key"]["key_id"] == first["record"]["key"]["key_id"]
                                        for f in report["findings"]), "Local incident missed custody")
        missing = dict(query, subject="urn:transeuroogs:kme:eagle-lu")
        code, report = local("lu", "/metadata/v1/trace", missing, ctx=auditor)
        self.require(code == 200 and not report["complete_within_supplied_scope"]
                     and "subject_history_unavailable" in report["gaps"],
                     "Missing provider history presented as complete")
        trust_file, query_file = self.directory / "trust.json", self.directory / "incident.json"
        evidence, output = self.directory / "evidence.ndjson", self.directory / "report.json"
        trust_file.write_text(json.dumps(self.trust))
        query_file.write_text(json.dumps(query))
        evidence.write_text("".join(json.dumps(p) + "\n" for p in pages))
        command = [str(self.binary), "trace", "--trust", str(trust_file), "--query", str(query_file),
                   "--evidence", str(evidence), "--audience", self.audience, "--out", str(output)]
        subprocess.run(command, check=True, capture_output=True)
        report = json.loads(output.read_text())
        finding = next(f for f in report["findings"] if f["key"]["key_id"] == first["record"]["key"]["key_id"])
        self.require({d["recipient"] for d in finding["delivery_commitments"]} == {"SAE-LU", "SAE-GR"},
                     "Offline tracing did not correlate both national deliveries")
        # A signed export cannot be edited to manufacture a source assertion.
        pages[0]["page"]["namespace"] = "tampered"
        evidence.write_text("".join(json.dumps(p) + "\n" for p in pages))
        command[-1] = str(self.directory / "must-not-exist.json")
        result = subprocess.run(command, capture_output=True)
        self.require(result.returncode != 0 and not (self.directory / "must-not-exist.json").exists(),
                     "Tampered evidence accepted")
        print(json.dumps({"result": "PASS", "metadata": True, "signed_events": len(events),
                          "provider_unknowns_preserved": True, "application_views_restricted": True,
                          "two_site_incident_trace": True, "tamper_rejected": True}))
