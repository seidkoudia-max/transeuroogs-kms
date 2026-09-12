package allocation_test

import (
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"testing"
	"time"
)

func TestMandatoryEvidenceFreshnessAndEntitlement(t *testing.T) {
	now := time.Now()
	generated := now.Add(-30 * time.Second)
	clock := int64(0)
	base := allocation.Facts{Source: "synthetic", Issuer: "urn:test:kms", Evidence: "local_observation", Generation: &generated, Collected: now.Add(-10 * time.Second), Expires: now.Add(time.Hour), ClockUncertaintyMS: &clock}
	r := testallocation.Rule()
	r.RequireEvidence = true
	r.MaxGenerationAgeSeconds = 60
	r.MaxLocalAgeSeconds = 20
	r.AllowedIssuers = []string{"urn:test:kms"}
	if got := allocation.Evaluate(r, base, now); got != "" {
		t.Fatal(got)
	}
	cases := []struct {
		name, want string
		change     func(*allocation.Facts)
	}{
		{"unknown generation", "generation_time_unknown", func(f *allocation.Facts) { f.Generation = nil }},
		{"unknown clock", "generation_time_unknown", func(f *allocation.Facts) { f.ClockUncertaintyMS = nil }},
		{"unverified claim", "evidence_unknown", func(f *allocation.Facts) { f.Evidence = "unverified_claim" }},
		{"wrong issuer", "issuer_denied", func(f *allocation.Facts) { f.Issuer = "urn:test:other" }},
		{"local ttl", "local_age_exceeded", func(f *allocation.Facts) { f.Collected = now.Add(-21 * time.Second) }},
		{"generation age", "generation_age_exceeded", func(f *allocation.Facts) { old := now.Add(-61 * time.Second); f.Generation = &old }},
		{"future generation", "generation_time_unknown", func(f *allocation.Facts) { future := now.Add(time.Second); f.Generation = &future }},
		{"expiry", "expired", func(f *allocation.Facts) { f.Expires = now }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := base
			c.change(&f)
			if got := allocation.Evaluate(r, f, now); got != c.want {
				t.Fatal(got)
			}
		})
	}
	r.AllowedSources = []string{"satellite"}
	base.Source = "satellite"
	if got := allocation.Evaluate(r, base, now); got != "satellite_not_entitled" {
		t.Fatal(got)
	}
	r.AllowSatellite = true
	if got := allocation.Evaluate(r, base, now); got != "" {
		t.Fatal(got)
	}
	r.Paused = true
	if got := allocation.Evaluate(r, base, now); got != "paused" {
		t.Fatal(got)
	}
}
func TestReplayScopeRecoveryAndCapacity(t *testing.T) {
	a := core.Association{Master: "A", Slave: "B"}
	setup := testallocation.Setup(a)
	setup.Config.MaxCommands = 1
	s, err := allocation.Open(setup, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	cmd := testallocation.Command(a, 0, testallocation.Rule())
	now := time.Now()
	got, err := s.Apply(setup, testallocation.Actor, cmd, now)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := s.Apply(setup, testallocation.Actor, cmd, now.Add(time.Second))
	if err != nil || !got.AppliedAt.Equal(replay.AppliedAt) {
		t.Fatal("replay changed result", err)
	}
	mutated := allocation.Clone(cmd)
	mutated.Rule.Paused = true
	if _, err = s.Apply(setup, testallocation.Actor, mutated, now); err != allocation.ErrConflict {
		t.Fatal(err)
	}
	if _, err = s.Apply(setup, testallocation.Actor, testallocation.Command(a, 1, testallocation.Rule()), now); err != core.ErrCapacity {
		t.Fatal(err)
	}
	if _, err = allocation.Open(setup, s, true); err != nil {
		t.Fatal(err)
	}
	if _, err = allocation.Open(nil, s, true); err == nil {
		t.Fatal("disabled persisted policy")
	}
	if _, err = allocation.Open(setup, nil, true); err == nil {
		t.Fatal("silently enabled legacy state")
	}
	changed := allocation.Clone(s)
	changed.Apps[0].Rule.Paused = true
	if _, err = allocation.Open(setup, changed, true); err == nil {
		t.Fatal("tampered state accepted")
	}
	if err = allocation.Authorize(setup, "urn:test:app", cmd); err != core.ErrUnauthorized {
		t.Fatal(err)
	}
}
