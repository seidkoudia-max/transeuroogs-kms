package federation_test

import (
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/federation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testfederation"
	"testing"
	"time"
)

func TestBindingsPendingSESAndIncidentReplay(t *testing.T) {
	a, b := core.Association{Master: "A", Slave: "B"}, core.Association{Master: "A", Slave: "C"}
	c := testfederation.Config(a, b)
	for _, mutation := range []func(*federation.Config){func(c *federation.Config) { c.Pools[1].Association = a }, func(c *federation.Config) { c.Pools[1].Ref.ID = c.Pools[0].Ref.ID }, func(c *federation.Config) { c.Pools[1].Gateways = c.Pools[0].Gateways }} {
		bad := federation.Clone(c)
		mutation(bad)
		if bad.Validate([]core.Association{a, b}) == nil {
			t.Fatal("ambiguous binding accepted")
		}
	}
	c.Pools[1].Contract.Mode = "ses-pending"
	s, e := federation.Open(c, nil, false, []core.Association{a, b})
	if e != nil {
		t.Fatal(e)
	}
	if s.Gate(a) != "" || s.Gate(b) != "needs_SES_input" || len(c.Pools[1].Contract.Needed()) != 10 {
		t.Fatal("missing SES input silently filled")
	}
	cmd := testfederation.Command(c, 0, core.NewID(), "hold")
	now := time.Now()
	if _, e = s.Apply("urn:test:controller", cmd, now); e != core.ErrUnauthorized {
		t.Fatal("controller gained incident authority")
	}
	for range 2 {
		if out, e := s.Apply(testfederation.Actor, cmd, now); e != nil || out.Revision != 1 {
			t.Fatal("idempotent action", e)
		}
	}
	bad := cmd
	bad.Operation = "release"
	if _, e = s.Apply(testfederation.Actor, bad, now); e == nil {
		t.Fatal("reused action ID changed operation")
	}
	restored, e := federation.Open(c, s, true, []core.Association{a, b})
	if e != nil || restored.Gate(a) != "incident_hold" {
		t.Fatal("lost hold", e)
	}
	i := s.Incidents[cmd.Incident]
	i.Held = false
	s.Incidents[cmd.Incident] = i
	if _, e = federation.Open(c, s, true, []core.Association{a, b}); e == nil {
		t.Fatal("mutated hold map accepted")
	}
	c.Pools[0].Ref.Revision++
	if _, e = federation.Open(c, restored, true, []core.Association{a, b}); e == nil {
		t.Fatal("mapping changed on restart")
	}
}

func TestEvidenceSignatureScopeAndExpiry(t *testing.T) {
	a, b := core.Association{Master: "A", Slave: "B"}, core.Association{Master: "A", Slave: "C"}
	c := testfederation.Config(a, b)
	now := time.Now().UTC()
	k, e := testfederation.Signing(c, now)
	if e != nil {
		t.Fatal(e)
	}
	c.Pools[0].RequireEvidence = true
	s, e := federation.Open(c, nil, false, []core.Association{a, b})
	if e != nil {
		t.Fatal(e)
	}
	id := core.NewID()
	v := testfederation.Evidence(c.Pools[0], id, now)
	token, e := federation.SignEvidence(v, k)
	if e != nil {
		t.Fatal(e)
	}
	if s.Check(a, id, now) != "provider_evidence_required" {
		t.Fatal("unknown evidence satisfied policy")
	}
	if e = s.PutEvidence(v.Pool.ID, token, now); e != nil || s.Check(a, id, now) != "" {
		t.Fatal("signed evidence rejected", e)
	}
	if e = s.PutEvidence(c.Pools[1].Ref.ID, token, now); e == nil {
		t.Fatal("cross-pool proof accepted")
	}
	if e = s.PutEvidence(v.Pool.ID, token[:len(token)-3]+"AAA", now); e == nil {
		t.Fatal("tampered proof accepted")
	}
	for _, mutate := range []func(*federation.Evidence){func(v *federation.Evidence) { v.Ready = false }, func(v *federation.Evidence) { v.Kind = "raw" }, func(v *federation.Evidence) { v.Pool.Purpose = "other" }, func(v *federation.Evidence) { v.Association = b }, func(v *federation.Evidence) { v.IssuedAt = now.Add(time.Second) }, func(v *federation.Evidence) { v.Origin = "satellite" }} {
		bad := v
		mutate(&bad)
		signed, _ := federation.SignEvidence(bad, k)
		if _, e = s.Verify(v.Pool.ID, signed, now); e == nil {
			t.Fatal("invalid scope/lifecycle accepted")
		}
	}
	if s.Check(a, id, now.Add(time.Minute)) == "" {
		t.Fatal("expired attestation used")
	}
	v.ID = core.NewID()
	conflicting, _ := federation.SignEvidence(v, k)
	if e = s.PutEvidence(v.Pool.ID, conflicting, now); e == nil {
		t.Fatal("immutable evidence replaced")
	}
	s.Config.Trust[0].Revoked = true
	if _, e = s.Verify(v.Pool.ID, token, now); e == nil {
		t.Fatal("revoked provider trusted")
	}
}
