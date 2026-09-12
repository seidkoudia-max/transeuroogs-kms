package storage

import (
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
)

var _ allocation.Manager = (*Persistent)(nil)

func (p *Persistent) ApplyCommand(actor string, c allocation.Command) (allocation.Commit, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.memory
	if p.broken {
		return allocation.Commit{}, durable.ErrState
	}
	if err := allocation.Authorize(m.setup, actor, c); err != nil {
		return allocation.Commit{}, err
	}
	next := allocation.Clone(m.allocation)
	result, err := next.Apply(m.setup, actor, c, m.now())
	if err != nil {
		return allocation.Commit{}, err
	}
	m.allocation = next
	if err = p.save(); err != nil {
		return allocation.Commit{}, err
	}
	return result, nil
}

func (p *Persistent) ManagementView(pairs []core.Association) (allocation.View, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.memory
	if p.broken || m.allocation == nil {
		return allocation.View{}, durable.ErrState
	}
	now := m.now()
	out := m.allocation.View(m.setup, pairs, now)
	for i := range out.Apps {
		app := &out.Apps[i]
		app.Pool = m.protection.Ref(app.Association)
		app.ProtectionGate = m.protection.Gate(app.Association)
		app.Counts.Capacity = m.capacity
		for _, k := range m.keys {
			if k.meta.Association != app.Association {
				continue
			}
			expire(k, now)
			for _, st := range []core.State{k.meta.MasterState, k.meta.SlaveState} {
				switch st {
				case core.Consumed:
					app.Counts.Delivered++
				case core.Reserved:
					app.Counts.Reserved++
				case core.Available:
					app.Counts.Available++
					if reason := m.policy(k, 1, now); reason != "" {
						app.Counts.Denied[reason]++
					} else {
						app.Counts.Eligible++
					}
				}
			}
		}
	}
	if err := p.save(); err != nil {
		return allocation.View{}, err
	}
	return out, nil
}
