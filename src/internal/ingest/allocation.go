package ingest

import (
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/upstream"
	"time"
)

var _ allocation.Manager = (*Repository)(nil)

func (r *Repository) policy(n int, collected, expires time.Time, ids ...core.KeyID) string {
	// Without the separately verified evidence adapter, TLS alone cannot attest origin.
	f := allocation.Facts{Source: "synthetic", Issuer: r.cfg.ServerIdentity, Evidence: "unverified_claim", Collected: collected, Expires: expires}
	if r.cfg.Profile != upstream.Profile {
		f.Source = "unknown"
		f.Evidence = "unknown"
	}
	if len(ids) == 0 && r.s.Protection != nil {
		if _, ok := r.provider.(EvidenceProvider); ok {
			return r.s.Allocation.Preflight(r.pair, n, r.now())
		}
	}
	for _, id := range ids {
		if reason := r.s.Protection.Check(r.pair, id, r.now()); reason != "" {
			return reason
		}
		facts := allocation.ProviderFacts(f, r.s.Protection, id, r.setup)
		if reason := r.s.Allocation.Check(r.pair, n, facts, r.now()); reason != "" {
			return reason
		}
	}
	if len(ids) > 0 {
		return ""
	}
	return r.s.Allocation.Check(r.pair, n, f, r.now())
}
func (r *Repository) ApplyCommand(actor string, c allocation.Command) (allocation.Commit, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.broken {
		return allocation.Commit{}, durable.ErrState
	}
	if err := allocation.Authorize(r.setup, actor, c); err != nil {
		return allocation.Commit{}, err
	}
	next := allocation.Clone(r.s.Allocation)
	result, err := next.Apply(r.setup, actor, c, r.now())
	if err != nil {
		return allocation.Commit{}, err
	}
	if next.Revision != r.s.Allocation.Revision && c.Service != nil && c.Service.Operation == "application_delete" {
		for _, k := range r.s.Keys {
			if !k.State.Terminal() {
				clear(k.Material)
				k.Material = nil
				k.State = core.Invalid
			}
		}
	}
	r.s.Allocation = next
	if err = r.save(); err != nil {
		return allocation.Commit{}, err
	}
	return result, nil
}
func (r *Repository) ManagementView(pairs []core.Association) (allocation.View, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.broken || r.s.Allocation == nil {
		return allocation.View{}, durable.ErrState
	}
	if err := r.expire(); err != nil {
		return allocation.View{}, err
	}
	out := r.s.Allocation.View(r.setup, pairs, r.now())
	for i := range out.Apps {
		app := &out.Apps[i]
		app.Pool = r.s.Protection.Ref(app.Association)
		app.ProtectionGate = r.s.Protection.Gate(app.Association)
		app.Counts.Capacity = r.capacity
		for _, k := range r.s.Keys {
			if k.State == core.Consumed {
				app.Counts.Delivered++
			}
			if k.State == core.Reserved {
				app.Counts.Reserved++
			}
		}
		// A management read stays local: it never blocks behind a fresh provider
		// request or claims a remote inventory observation is currently available.
	}
	return out, nil
}

func (r *Repository) ManagementChanges(pairs []core.Association, after uint64, limit int) (allocation.ChangePage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.broken {
		return allocation.ChangePage{}, durable.ErrState
	}
	return r.s.Allocation.Changes(pairs, after, limit)
}
