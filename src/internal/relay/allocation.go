package relay

import (
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"time"
)

var _ allocation.Manager = (*Engine)(nil)

func (e *Engine) policy(s *state, r *record, n int, now time.Time) string {
	if reason := s.Protection.Check(r.Pair, r.ID, now); reason != "" {
		return reason
	}
	f := allocation.LocalFacts(r.Source, r.Created, r.Expires, e.setup)
	if peer, ok := e.cfg.Peers[r.Sender]; ok {
		f.Issuer = peer.Identity
	}
	f = allocation.ProviderFacts(f, s.Protection, r.ID, e.setup)
	return s.Allocation.Check(r.Pair, n, f, now)
}
func (e *Engine) ApplyCommand(actor string, c allocation.Command) (allocation.Commit, error) {
	if err := allocation.Authorize(e.setup, actor, c); err != nil {
		return allocation.Commit{}, err
	}
	var out allocation.Commit
	err := e.change(func(s *state) error {
		before := s.Allocation.Revision
		var err error
		out, err = s.Allocation.Apply(e.setup, actor, c, e.now())
		if err != nil {
			return err
		}
		if s.Allocation.Revision != before && c.Service != nil && c.Service.Operation == "application_delete" {
			for _, r := range s.Keys {
				if r.Pair == c.Association {
					startVoid(s, r, "")
				}
			}
		}
		if len(c.Routes) > 0 && s.Allocation.Revision != before {
			for _, id := range s.Order {
				r := s.Keys[id]
				if r.Pair == c.Association && !r.Sent && !r.Ready && !r.Voiding && !r.Delivered && r.Role != "target" {
					r.Candidates = e.candidates(s, r.Pair.Slave, r.Sender)
				}
			}
		}
		return nil
	})
	if err != nil {
		return allocation.Commit{}, err
	}
	return out, nil
}
func (e *Engine) ManagementView(pairs []core.Association) (allocation.View, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.broken || e.s.Allocation == nil {
		return allocation.View{}, errJournal
	}
	now := e.now()
	out := e.s.Allocation.View(e.setup, pairs, now)
	for i := range out.Apps {
		app := &out.Apps[i]
		app.Pool = e.s.Protection.Ref(app.Association)
		app.ProtectionGate = e.s.Protection.Gate(app.Association)
		app.Counts.Capacity = e.capacity
		for _, r := range e.s.Keys {
			if r.Pair != app.Association {
				continue
			}
			if r.Sent && !r.Ready && !r.Delivered && !r.Voiding {
				app.Counts.InFlight[r.Next]++
			}
			if r.Delivered {
				app.Counts.Delivered++
			}
			if r.Token != "" && !r.Voiding && now.Before(r.Expires) {
				app.Counts.Reserved++
			}
			if r.Role == "relay" || r.Token != "" || !usable(r, now) {
				continue
			}
			app.Counts.Available++
			if reason := e.policy(&e.s, r, 1, now); reason != "" {
				app.Counts.Denied[reason]++
			} else {
				app.Counts.Eligible++
			}
		}
	}
	return out, nil
}

func (e *Engine) ManagementChanges(pairs []core.Association, after uint64, limit int) (allocation.ChangePage, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.broken {
		return allocation.ChangePage{}, errJournal
	}
	return e.s.Allocation.Changes(pairs, after, limit)
}
