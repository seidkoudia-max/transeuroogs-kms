package relay

import (
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/federation"
)

var _ federation.Manager = (*Engine)(nil)

func (e *Engine) ProtectionView(pools []string, sae string) (federation.View, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.broken || e.s.Protection == nil {
		return federation.View{}, errJournal
	}
	return federation.Clone(e.s.Protection.View(pools, sae)), nil
}
func (e *Engine) ApplyProtection(actor string, c federation.Command) (federation.Result, error) {
	var out federation.Result
	err := e.change(func(s *state) error {
		if s.Protection == nil {
			return core.ErrUnauthorized
		}
		before := s.Protection.Revision
		var err error
		out, err = s.Protection.Apply(actor, c, e.now())
		if err != nil || before == s.Protection.Revision {
			return err
		}
		if c.Operation == "invalidate" {
			out.RemoteStatus = "void_pending"
			for _, r := range s.Keys {
				if r.Pool.ID != c.Pool {
					continue
				}
				if r.Delivered {
					out.AlreadyDelivered++
				} else if !r.Voiding {
					out.Invalidated++
				}
				startVoid(s, r, "")
			}
		}
		s.Protection.Actions[len(s.Protection.Actions)-1] = out
		return nil
	})
	if err != nil {
		return federation.Result{}, err
	}
	return out, nil
}
func (e *Engine) RecordReceipt(receipt federation.Receipt) error {
	return e.change(func(s *state) error {
		r := s.Keys[receipt.Key]
		if r == nil || s.Protection == nil {
			return core.ErrUnavailable
		}
		m := core.Metadata{ID: r.ID, Pool: r.Pool, Association: r.Pair}
		if r.Delivered && r.Role == "source" {
			m.MasterState = core.Consumed
		}
		if r.Delivered && r.Role == "target" {
			m.SlaveState = core.Consumed
		}
		return s.Protection.AddReceipt(receipt, m, e.now())
	})
}
func (e *Engine) ImportEvidence(actor, pool, token string) error {
	return e.change(func(s *state) error {
		if !s.Protection.Authorized(actor, pool, true) {
			return core.ErrUnauthorized
		}
		v, err := s.Protection.Verify(pool, token, e.now())
		if err != nil {
			return err
		}
		r := s.Keys[v.Key]
		if r == nil || r.Pool != v.Pool {
			return core.ErrUnavailable
		}
		return s.Protection.PutEvidence(pool, token, e.now())
	})
}
