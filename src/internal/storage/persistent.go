package storage

import (
	"encoding/json"
	"sync"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/federation"
)

type savedEntry struct {
	Meta           core.Metadata
	MasterMaterial []byte
	SlaveMaterial  []byte
}
type savedReservation struct {
	Pool        core.PoolRef `json:",omitzero"`
	Association core.Association
	IDs         []core.KeyID
}
type memoryState struct {
	Protection   *federation.State `json:",omitempty"`
	Allocation   *allocation.State `json:",omitempty"`
	Version      int
	Capacity     int
	Binding      string
	Keys         map[core.KeyID]savedEntry
	Order        []core.KeyID
	Reservations map[core.KeyID]savedReservation
}
type Persistent struct {
	mu      sync.Mutex
	memory  *Memory
	store   durable.Store
	binding string
	broken  bool
}

var _ core.Repository = (*Persistent)(nil)

func OpenPersistent(capacity int, binding string, store durable.Store, raw []byte, options ...*allocation.Setup) (*Persistent, error) {
	return OpenPersistentControlled(capacity, binding, store, raw, nil, options...)
}

func OpenPersistentControlled(capacity int, binding string, store durable.Store, raw []byte, controls *federation.Config, options ...*allocation.Setup) (*Persistent, error) {
	defer clear(raw)
	if store == nil || len(options) > 1 {
		return nil, core.ErrInvalid
	}
	if !durable.PlainSnapshot(raw) {
		store.Close()
		return nil, durable.ErrState
	}
	m, err := NewMemory(capacity, nil)
	if err != nil {
		store.Close()
		return nil, err
	}
	p := &Persistent{memory: m, store: store, binding: binding}
	m.setup = allocation.Select(options)
	if raw != nil {
		var s memoryState
		if json.Unmarshal(raw, &s) != nil || s.Version != 1 || s.Capacity != capacity || s.Binding != binding || s.Keys == nil || s.Reservations == nil || len(s.Keys) > capacity {
			p.Close()
			return nil, durable.ErrState
		}
		m.allocation = s.Allocation
		m.protection = s.Protection
		for id, e := range s.Keys {
			if !id.Valid() || e.Meta.ID != id || !e.Meta.Association.Valid() {
				p.Close()
				return nil, durable.ErrState
			}
			m.keys[id] = &entry{meta: e.Meta, master: e.MasterMaterial, slave: e.SlaveMaterial}
		}
		seen := map[core.KeyID]bool{}
		for _, id := range s.Order {
			if m.keys[id] == nil || seen[id] {
				p.Close()
				return nil, durable.ErrState
			}
			seen[id] = true
		}
		if len(seen) != len(m.keys) {
			p.Close()
			return nil, durable.ErrState
		}
		m.order = s.Order
		for token, r := range s.Reservations {
			if !token.Valid() || !r.Association.Valid() || len(r.IDs) < 1 || len(r.IDs) > core.MaxBatch {
				p.Close()
				return nil, durable.ErrState
			}
			for _, id := range r.IDs {
				if m.keys[id] == nil || m.keys[id].meta.Association != r.Association {
					p.Close()
					return nil, durable.ErrState
				}
			}
			m.reservations[token] = reservation{r.Pool, r.Association, r.IDs}
		}
	}
	var pairs []core.Association
	if controls != nil {
		for _, p := range controls.Pools {
			pairs = append(pairs, p.Association)
		}
	}
	m.protection, err = federation.Open(controls, m.protection, raw != nil, pairs)
	if err != nil {
		p.Close()
		return nil, durable.ErrState
	}
	for _, r := range m.reservations {
		if r.pool != m.protection.Ref(r.association) {
			p.Close()
			return nil, durable.ErrState
		}
	}
	for _, k := range m.keys {
		if k.meta.Pool != m.protection.Ref(k.meta.Association) {
			p.Close()
			return nil, durable.ErrState
		}
	}
	m.allocation, err = allocation.Open(m.setup, m.allocation, raw != nil)
	if err != nil {
		p.Close()
		return nil, durable.ErrState
	}
	if err = p.save(); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}
func (p *Persistent) save() error {
	if p.broken {
		return durable.ErrState
	}
	m := p.memory
	s := memoryState{Protection: m.protection, Allocation: m.allocation, Version: 1, Capacity: m.capacity, Binding: p.binding, Keys: map[core.KeyID]savedEntry{}, Order: m.order, Reservations: map[core.KeyID]savedReservation{}}
	for id, e := range m.keys {
		expire(e, m.now())
		s.Keys[id] = savedEntry{e.meta, e.master, e.slave}
	}
	for id, r := range m.reservations {
		s.Reservations[id] = savedReservation{r.pool, r.association, r.ids}
	}
	b, err := json.Marshal(s)
	defer clear(b)
	if err == nil {
		err = p.store.Save(b)
	}
	if err != nil {
		p.broken = true
		return durable.ErrState
	}
	return nil
}
func (p *Persistent) StoreKey(k core.Key) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken {
		return durable.ErrState
	}
	if err := p.memory.StoreKey(k); err != nil {
		return err
	}
	return p.save()
}
func (p *Persistent) ReserveKeys(a core.Association, n int) (core.Reservation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken {
		return core.Reservation{}, durable.ErrState
	}
	r, err := p.memory.ReserveKeys(a, n)
	if e := p.save(); e != nil {
		return core.Reservation{}, e
	}
	return r, err
}
func (p *Persistent) consume(fn func() ([]core.Delivery, error)) ([]core.Delivery, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken {
		return nil, durable.ErrState
	}
	d, err := fn()
	if e := p.save(); e != nil {
		for _, k := range d {
			clear(k.Material)
		}
		return nil, e
	}
	return d, err
}
func (p *Persistent) ConsumeReservation(a core.Association, id core.KeyID) ([]core.Delivery, error) {
	return p.consume(func() ([]core.Delivery, error) { return p.memory.ConsumeReservation(a, id) })
}
func (p *Persistent) ConsumePeerKeys(a core.Association, ids []core.KeyID) ([]core.Delivery, error) {
	return p.consume(func() ([]core.Delivery, error) { return p.memory.ConsumePeerKeys(a, ids) })
}
func (p *Persistent) InvalidateKey(id core.KeyID) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken {
		return durable.ErrState
	}
	err := p.memory.InvalidateKey(id)
	if e := p.save(); e != nil {
		return e
	}
	return err
}
func (p *Persistent) Metadata(id core.KeyID) (core.Metadata, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken {
		return core.Metadata{}, durable.ErrState
	}
	m, err := p.memory.Metadata(id)
	if e := p.save(); e != nil {
		return core.Metadata{}, e
	}
	return m, err
}
func (p *Persistent) Inventory(a core.Association) core.Inventory {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken {
		return core.Inventory{Capacity: p.memory.capacity}
	}
	i := p.memory.Inventory(a)
	if p.save() != nil {
		i.Available = 0
	}
	return i
}
func (p *Persistent) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.broken = true
	for _, e := range p.memory.keys {
		clear(e.master)
		clear(e.slave)
	}
	p.store.Close()
}
