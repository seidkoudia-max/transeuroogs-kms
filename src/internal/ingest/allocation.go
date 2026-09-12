package ingest

import (
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
	"time"
)

var _ allocation.Manager = (*Repository)(nil)

func (r *Repository) policy(n int, collected, expires time.Time) string {
	// The only accepted upstream profile is synthetic. Its 014 response contains
	// no authenticated generation metadata; TLS identity does not attest origin.
	f := allocation.Facts{Source: "synthetic", Issuer: r.cfg.ServerIdentity, Evidence: "unverified_claim", Collected: collected, Expires: expires}
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
