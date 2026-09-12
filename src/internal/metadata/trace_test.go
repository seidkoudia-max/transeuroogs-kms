package metadata

import (
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"slices"
	"testing"
	"time"
)

func TestIncidentUsesCustodyInsteadOfGenerationAndFindsDeliveries(t *testing.T) {
	f := fixtureFor(t, 100)
	start := f.now
	old, cleared := f.key(), f.key()
	generation := start.Add(-24 * time.Hour)
	old.GenerationTime = &generation
	f.keys[old.Key.ID] = old
	f.keys[cleared.Key.ID] = cleared
	if e := f.save(); e != nil {
		t.Fatal(e)
	}
	f.now = start.Add(time.Second)
	cleared.HoldingMaterial = false
	cleared.MasterState = core.Consumed
	cleared.SlaveState = core.Consumed
	f.keys[cleared.Key.ID] = cleared
	if e := f.save(); e != nil {
		t.Fatal(e)
	}
	f.now = start.Add(10 * time.Second)
	old.MasterState = core.Consumed
	old.SlaveState = core.Consumed
	old.HoldingMaterial = false
	f.keys[old.Key.ID] = old
	if e := f.save(); e != nil {
		t.Fatal(e)
	}
	z := int64(0)
	q := Query{IncidentID: core.NewID(), Subject: f.c.Issuer, Kind: "material_exposure", Start: start.Add(4 * time.Second), End: start.Add(6 * time.Second), ClockUncertaintyMS: &z}
	report, e := f.store.Trace(q, []core.Association{old.Key.Association})
	if e != nil || len(report.Findings) != 1 {
		t.Fatal("wrong incident set", e)
	}
	got := report.Findings[0]
	if got.Key.ID != old.Key.ID || got.Classification != "affected" || len(got.Deliveries) != 2 || got.Deliveries[0].ApplicationReceipt != "unknown" {
		t.Fatal("exposure/delivery semantics wrong")
	}
	q.Subject = "urn:unseen:provider"
	report, e = f.store.Trace(q, []core.Association{old.Key.Association})
	if e != nil || report.Complete || !slices.Contains(report.Gaps, "subject_history_unavailable") {
		t.Fatal("missing provider presented as complete")
	}
}

func TestUnknownClocksPartialCoverageAndDistinctPaths(t *testing.T) {
	f := fixtureFor(t, 100)
	start := f.now
	r := f.key()
	f.keys[r.Key.ID] = r
	if e := f.save(); e != nil {
		t.Fatal(e)
	}
	f.now = start.Add(time.Second)
	r.HoldingMaterial = false
	f.keys[r.Key.ID] = r
	if e := f.save(); e != nil {
		t.Fatal(e)
	}
	p := f.page(t)
	es := []Event{}
	for _, e := range p.Page.Events {
		es = append(es, e.Event)
	}
	for i := range es {
		es[i].ClockUncertaintyMS = nil
	}
	q := Query{IncidentID: core.NewID(), Subject: f.c.Issuer, Kind: "material_exposure", Start: start.Add(5 * time.Second), End: start.Add(6 * time.Second)}
	c := []Coverage{{Issuer: f.c.Issuer, Namespace: f.c.Namespace, StartedAt: start, ObservedAt: f.now, Complete: false, ProviderHistory: "unknown"}}
	report, e := Trace(q, es, c)
	if e != nil || report.Complete || len(report.Findings) != 1 || report.Findings[0].Classification != "possibly_affected" {
		t.Fatal("unknown clocks or coverage silently excluded")
	}
	other := clone(es[0])
	other.ID = core.NewID()
	other.Issuer = "urn:test:node:b"
	other.Record.Key.ID = core.NewID()
	es = append(es, other)
	report, e = Trace(q, es, c)
	if e != nil || len(report.Findings) != 1 {
		t.Fatal("distinct path/key spuriously linked")
	}
}

func TestUpstreamCoverageMustIncludeExactNamespacePairAndKey(t *testing.T) {
	f := fixtureFor(t, 100)
	r := f.key()
	r.Upstream = "urn:test:upstream"
	f.keys[r.Key.ID] = r
	if err := f.save(); err != nil {
		t.Fatal(err)
	}
	p := f.page(t)
	q := Query{IncidentID: core.NewID(), Subject: r.Upstream, Kind: "material_exposure", Start: f.now.Add(-time.Second), End: f.now.Add(time.Second)}
	for _, kind := range []string{"namespace", "association", "missing_key"} {
		t.Run(kind, func(t *testing.T) {
			upstream := clone(p.Page.Events[0].Event)
			upstream.Issuer = r.Upstream
			upstream.Record.Upstream = ""
			c := Coverage{Issuer: r.Upstream, Namespace: f.c.Namespace, Scope: []core.Association{r.Key.Association}, StartedAt: q.Start.Add(-time.Hour), ObservedAt: q.End.Add(time.Hour), Complete: true}
			switch kind {
			case "namespace":
				c.Namespace = "unrelated"
				upstream.Record.Key.Namespace = c.Namespace
			case "association":
				c.Scope = []core.Association{{Master: "X", Slave: "Y"}}
				upstream.Record.Key.Association = c.Scope[0]
			case "missing_key":
				upstream.Record.Key.ID = core.NewID()
			}
			report, err := Trace(q, []Event{p.Page.Events[0].Event, upstream}, []Coverage{c})
			if err != nil || report.Complete || !slices.Contains(report.Gaps, "upstream_history_unavailable") {
				t.Fatal("unrelated upstream coverage hid missing evidence", err)
			}
			found := false
			for _, finding := range report.Findings {
				if finding.Key.ID == r.Key.ID && finding.Key.Association == r.Key.Association && finding.Key.Namespace == f.c.Namespace {
					found = finding.Classification == "unknown"
				}
			}
			if !found {
				t.Fatal("missing upstream key binding not explicit")
			}
		})
	}
}
