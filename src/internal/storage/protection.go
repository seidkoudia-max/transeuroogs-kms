package storage

import (
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/federation"
)

var _ federation.Manager = (*Persistent)(nil)

func (p *Persistent) ProtectionView(pools []string, sae string) (federation.View, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken || p.memory.protection == nil {
		return federation.View{}, durable.ErrState
	}
	return federation.Clone(p.memory.protection.View(pools, sae)), nil
}
func (p *Persistent) ApplyProtection(actor string, c federation.Command) (federation.Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.memory
	if p.broken || m.protection == nil {
		return federation.Result{}, durable.ErrState
	}
	next := federation.Clone(m.protection)
	before := next.Revision
	out, err := next.Apply(actor, c, m.now())
	if err != nil {
		return out, err
	}
	if next.Revision == before {
		return out, nil
	}
	if c.Operation == "invalidate" {
		for _, e := range m.keys {
			if e.meta.Pool.ID != c.Pool {
				continue
			}
			expire(e, m.now())
			for _, st := range []core.State{e.meta.MasterState, e.meta.SlaveState} {
				if st == core.Consumed {
					out.AlreadyDelivered++
				} else if !st.Terminal() {
					out.Invalidated++
				}
			}
			_ = m.InvalidateKey(e.meta.ID)
		}
	}
	next.Actions[len(next.Actions)-1] = out
	m.protection = next
	if err = p.save(); err != nil {
		return federation.Result{}, err
	}
	return out, nil
}
func (p *Persistent) RecordReceipt(r federation.Receipt) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken || p.memory.protection == nil {
		return durable.ErrState
	}
	m, e := p.memory.Metadata(r.Key)
	if e != nil {
		return e
	}
	if e = p.memory.protection.AddReceipt(r, m, p.memory.now()); e != nil {
		return e
	}
	return p.save()
}
func (p *Persistent) ImportEvidence(actor, pool, token string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.memory.protection
	if p.broken || s == nil {
		return durable.ErrState
	}
	if !s.Authorized(actor, pool, true) {
		return core.ErrUnauthorized
	}
	v, e := s.Verify(pool, token, p.memory.now())
	if e != nil {
		return e
	}
	m, e := p.memory.Metadata(v.Key)
	if e != nil || m.Pool != v.Pool {
		return core.ErrUnavailable
	}
	if e = s.PutEvidence(pool, token, p.memory.now()); e != nil {
		return e
	}
	return p.save()
}
