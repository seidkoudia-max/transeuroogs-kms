package metadata

import (
	"slices"
	"sort"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
)

type Query struct {
	IncidentID         core.KeyID `json:"incident_id"`
	Subject            string     `json:"subject"`
	Kind               string     `json:"kind"`
	Start              time.Time  `json:"start"`
	End                time.Time  `json:"end"`
	ClockUncertaintyMS *int64     `json:"clock_uncertainty_ms"`
	Limit              int        `json:"limit,omitempty"`
}

type Coverage struct {
	Scope           []core.Association `json:"association_scope"`
	Issuer          string             `json:"issuer"`
	Namespace       string             `json:"namespace"`
	StartedAt       time.Time          `json:"history_started_at"`
	ObservedAt      time.Time          `json:"observed_at"`
	Watermark       uint64             `json:"watermark"`
	Complete        bool               `json:"retained_history_complete"`
	ProviderHistory string             `json:"provider_history"`
}

type EventRef struct {
	Issuer string     `json:"issuer"`
	ID     core.KeyID `json:"event_id"`
}
type Delivery struct {
	Issuer             string     `json:"issuer"`
	Recipient          string     `json:"recipient"`
	CommittedAt        time.Time  `json:"committed_at"`
	Event              core.KeyID `json:"event_id"`
	ApplicationReceipt string     `json:"application_receipt"`
}
type Disposition struct {
	Issuer  string     `json:"issuer"`
	Master  core.State `json:"master_state,omitempty"`
	Slave   core.State `json:"slave_state,omitempty"`
	Voiding bool       `json:"voiding"`
}
type Finding struct {
	Key            KeyRef        `json:"key"`
	Classification string        `json:"classification"`
	Reasons        []string      `json:"reasons"`
	Evidence       []EventRef    `json:"evidence"`
	Deliveries     []Delivery    `json:"delivery_commitments"`
	Disposition    []Disposition `json:"dispositions"`
}
type UncertainAttempt struct {
	Issuer  string      `json:"issuer"`
	Attempt AttemptView `json:"attempt"`
}
type Report struct {
	Profile           string             `json:"profile"`
	Query             Query              `json:"query"`
	Scope             string             `json:"scope"`
	Complete          bool               `json:"complete_within_supplied_scope"`
	Coverage          []Coverage         `json:"coverage"`
	Gaps              []string           `json:"gaps"`
	Findings          []Finding          `json:"findings"`
	UncertainAttempts []UncertainAttempt `json:"uncertain_attempts"`
}

func (q Query) Validate() error {
	if !q.IncidentID.Valid() || !name(q.Subject) || (q.Kind != "material_exposure" && q.Kind != "issuer_compromise") || q.Start.IsZero() || !q.End.After(q.Start) || q.End.Sub(q.Start) > 31*24*time.Hour || q.Limit < 0 || q.Limit > 128 {
		return core.ErrInvalid
	}
	if q.ClockUncertaintyMS != nil && (*q.ClockUncertaintyMS < 0 || *q.ClockUncertaintyMS > 60000) {
		return core.ErrInvalid
	}
	return nil
}

// overlap returns 0 outside, 2 possibly exposed, 3 affected under the supplied
// incident assumptions. Unknown clock bounds cannot establish non-overlap.
func overlap(start, end time.Time, uncertainty *int64, q Query) int {
	if uncertainty == nil || q.ClockUncertaintyMS == nil {
		return 2
	}
	u := time.Duration(*uncertainty+*q.ClockUncertaintyMS) * time.Millisecond
	if !start.Add(-u).Before(q.End) || !end.Add(u).After(q.Start) {
		return 0
	}
	if start.Add(u).Before(q.End) && end.Add(-u).After(q.Start) {
		return 3
	}
	return 2
}

// Trace operates on verified, caller-authorised events only. It follows custody
// of unchanged keys across supplied node histories, never equates distinct IDs
// on alternate paths, and never treats delivery commitment as application use.
func Trace(q Query, events []Event, coverage []Coverage) (Report, error) {
	if q.Validate() != nil || len(events) > 100000 || len(coverage) == 0 || len(coverage) > 64 {
		return Report{}, core.ErrInvalid
	}
	if q.Limit == 0 {
		q.Limit = 100
	}
	report := Report{Profile: Profile, Query: q, Scope: "supplied_local_histories; no_global_clearance", Complete: true, Coverage: clone(coverage), Gaps: []string{}, Findings: []Finding{}, UncertainAttempts: []UncertainAttempt{}}
	gap := func(s string) {
		if !slices.Contains(report.Gaps, s) {
			report.Gaps = append(report.Gaps, s)
		}
		report.Complete = false
	}
	byIssuer := map[string]Coverage{}
	for _, c := range coverage {
		byIssuer[c.Issuer] = c
		if len(c.Scope) == 0 {
			gap("association_scope_unspecified")
		}
		if !c.Complete {
			gap("partial_event_history")
		}
		if c.Issuer == q.Subject && (q.Start.Before(c.StartedAt) || q.End.After(c.ObservedAt)) {
			gap("incident_outside_recorded_coverage")
		}
	}
	if _, ok := byIssuer[q.Subject]; !ok {
		gap("subject_history_unavailable")
	}
	type location struct {
		Issuer string
		Key    KeyRef
	}
	groups := map[location][]Event{}
	attempts := map[string]UncertainAttempt{}
	for _, e := range events {
		if e.Record != nil {
			k := location{e.Issuer, e.Record.Key}
			groups[k] = append(groups[k], e)
		}
		if e.Attempt != nil {
			attempts[e.Issuer+"/"+e.Attempt.Reference] = UncertainAttempt{e.Issuer, *e.Attempt}
		}
	}
	found := map[KeyRef]*Finding{}
	strength := map[KeyRef]int{}
	add := func(e Event, n int, reason string) {
		if n == 0 {
			return
		}
		k := e.Record.Key
		f := found[k]
		if f == nil {
			f = &Finding{Key: k, Reasons: []string{}, Evidence: []EventRef{}, Deliveries: []Delivery{}, Disposition: []Disposition{}}
			found[k] = f
		}
		if n > strength[k] {
			strength[k] = n
		}
		if !slices.Contains(f.Reasons, reason) {
			f.Reasons = append(f.Reasons, reason)
		}
		ref := EventRef{e.Issuer, e.ID}
		if !slices.Contains(f.Evidence, ref) {
			f.Evidence = append(f.Evidence, ref)
		}
	}
	for loc, es := range groups {
		sort.Slice(es, func(i, j int) bool { return es[i].Sequence < es[j].Sequence })
		groups[loc] = es
		if loc.Issuer != q.Subject {
			for _, e := range es {
				if e.Record.Upstream == q.Subject {
					c, ok := byIssuer[q.Subject]
					_, hasKey := groups[location{q.Subject, loc.Key}]
					if !ok || !c.Complete || c.Namespace != loc.Key.Namespace || !slices.Contains(c.Scope, loc.Key.Association) || !hasKey || q.Start.Before(c.StartedAt) || q.End.After(c.ObservedAt) {
						add(e, 1, "upstream_history_unknown")
						gap("upstream_history_unavailable")
					}
				}
			}
			continue
		}
		c := byIssuer[loc.Issuer]
		if q.Start.Before(c.StartedAt) || q.End.After(c.ObservedAt) || !c.Complete {
			add(es[0], 1, "local_history_gap")
		}
		var held *Event
		for i := range es {
			e := es[i]
			if q.Kind == "issuer_compromise" {
				n := overlap(e.RecordedAt, e.RecordedAt.Add(time.Nanosecond), e.ClockUncertaintyMS, q)
				add(e, n, "issuer_statement_in_incident_window")
				continue
			}
			if e.Record.HoldingMaterial && held == nil {
				x := e
				held = &x
			}
			if !e.Record.HoldingMaterial && held != nil {
				add(*held, overlap(held.RecordedAt, e.RecordedAt, e.ClockUncertaintyMS, q), "custody_overlaps_incident")
				held = nil
			}
			// Slave ingestion can receive and burn bytes between two snapshots.
			// Its request/commit bounds are conservative, not invented custody times.
			if (e.Record.MasterState == core.Consumed || e.Record.SlaveState == core.Consumed || e.Record.Uncertain) && i > 0 && !es[i-1].Record.HoldingMaterial && !e.Record.HoldingMaterial {
				n := overlap(e.Record.CollectionIntent, e.RecordedAt, e.ClockUncertaintyMS, q)
				if n > 0 {
					add(e, 2, "transient_or_uncertain_intake_interval")
				}
			}
		}
		if held != nil {
			add(*held, overlap(held.RecordedAt, c.ObservedAt, held.ClockUncertaintyMS, q), "custody_overlaps_incident")
		}
	}
	// The same compromised key can affect earlier ciphertext as well as later
	// deliveries. Include ALL known commitments for the exact key/pair binding.
	for loc, es := range groups {
		f := found[loc.Key]
		if f == nil {
			continue
		}
		for _, e := range es {
			for _, d := range []struct{ action, recipient string }{{"master_CONSUMED", loc.Key.Association.Master}, {"slave_CONSUMED", loc.Key.Association.Slave}} {
				if slices.Contains(e.Actions, d.action) {
					f.Deliveries = append(f.Deliveries, Delivery{loc.Issuer, d.recipient, e.RecordedAt, e.ID, "unknown"})
				}
			}
		}
		last := es[len(es)-1].Record
		f.Disposition = append(f.Disposition, Disposition{loc.Issuer, last.MasterState, last.SlaveState, last.Voiding})
	}
	keys := make([]KeyRef, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { a, _ := marshal(keys[i]); b, _ := marshal(keys[j]); return string(a) < string(b) })
	for _, k := range keys {
		if len(report.Findings) == q.Limit {
			gap("result_limit")
			break
		}
		f := found[k]
		f.Classification = map[int]string{1: "unknown", 2: "possibly_affected", 3: "affected"}[strength[k]]
		sort.Strings(f.Reasons)
		sort.Slice(f.Evidence, func(i, j int) bool {
			return f.Evidence[i].Issuer+string(f.Evidence[i].ID) < f.Evidence[j].Issuer+string(f.Evidence[j].ID)
		})
		sort.Slice(f.Deliveries, func(i, j int) bool {
			return f.Deliveries[i].Issuer+string(f.Deliveries[i].Event) < f.Deliveries[j].Issuer+string(f.Deliveries[j].Event)
		})
		sort.Slice(f.Disposition, func(i, j int) bool { return f.Disposition[i].Issuer < f.Disposition[j].Issuer })
		report.Findings = append(report.Findings, *f)
	}
	refs := []string{}
	for ref := range attempts {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		a := attempts[ref]
		if a.Issuer == q.Subject && (a.Attempt.Status == "uncertain" || a.Attempt.Status == "pending") {
			if len(report.UncertainAttempts) == q.Limit {
				gap("attempt_limit")
				break
			}
			report.UncertainAttempts = append(report.UncertainAttempts, a)
			gap("uncertain_upstream_attempts")
		}
	}
	sort.Strings(report.Gaps)
	return clone(report), nil
}
