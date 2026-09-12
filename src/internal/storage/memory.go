// Package storage implements the laboratory's ephemeral key repository.
package storage

import (
	"sync"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/federation"
)

type entry struct {
	meta   core.Metadata
	master []byte
	slave  []byte
}

type reservation struct {
	pool        core.PoolRef
	association core.Association
	ids         []core.KeyID
}

type Memory struct {
	protection   *federation.State
	allocation   *allocation.State
	setup        *allocation.Setup
	mu           sync.Mutex
	capacity     int
	now          func() time.Time
	keys         map[core.KeyID]*entry
	order        []core.KeyID
	reservations map[core.KeyID]reservation
}

var _ core.Repository = (*Memory)(nil)

func NewMemory(capacity int, clock func() time.Time) (*Memory, error) {
	if capacity < 1 || capacity > 100000 {
		return nil, core.ErrInvalid
	}
	if clock == nil {
		clock = time.Now
	}
	return &Memory{capacity: capacity, now: clock, keys: make(map[core.KeyID]*entry), reservations: make(map[core.KeyID]reservation)}, nil
}

func (m *Memory) StoreKey(k core.Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ref := m.protection.Ref(k.Association)
	if (!k.Pool.Empty() && k.Pool != ref) || m.protection.Gate(k.Association) != "" {
		return core.ErrUnauthorized
	}
	k.Pool = ref
	if err := k.Validate(m.now()); err != nil {
		return err
	}
	if _, ok := m.keys[k.ID]; ok {
		return core.ErrDuplicate
	}
	if len(m.keys) >= m.capacity {
		return core.ErrCapacity
	}
	m.keys[k.ID] = &entry{
		meta:   core.Metadata{Pool: k.Pool, ID: k.ID, Association: k.Association, Source: k.Source, CreatedAt: k.CreatedAt, ExpiresAt: k.ExpiresAt, MasterState: core.Available, SlaveState: core.Reserved},
		master: append([]byte(nil), k.Material...), slave: append([]byte(nil), k.Material...),
	}
	m.order = append(m.order, k.ID)
	return nil
}

// expire is called under the repository lock with one clock snapshot per batch.
func expire(e *entry, now time.Time) {
	if now.Before(e.meta.ExpiresAt) {
		return
	}
	if !e.meta.MasterState.Terminal() {
		e.meta.MasterState = core.Expired
		clear(e.master)
		e.master = nil
	}
	if !e.meta.SlaveState.Terminal() {
		e.meta.SlaveState = core.Expired
		clear(e.slave)
		e.slave = nil
	}
}

func (m *Memory) ReserveKeys(a core.Association, count int) (core.Reservation, error) {
	if !a.Valid() || count < 1 || count > core.MaxBatch {
		return core.Reservation{}, core.ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	ids := make([]core.KeyID, 0, count)
	for _, id := range m.order {
		e := m.keys[id]
		expire(e, now)
		if e.meta.Association == a && e.meta.MasterState == core.Available && m.policy(e, count, now) == "" {
			ids = append(ids, id)
			if len(ids) == count {
				break
			}
		}
	}
	if len(ids) != count {
		return core.Reservation{}, core.ErrUnavailable
	}
	token := core.NewID()
	for {
		if _, exists := m.reservations[token]; !exists {
			break
		}
		token = core.NewID()
	}
	for _, id := range ids {
		m.keys[id].meta.MasterState = core.Reserved
	}
	m.reservations[token] = reservation{pool: m.protection.Ref(a), association: a, ids: append([]core.KeyID(nil), ids...)}
	return core.Reservation{Pool: m.protection.Ref(a), Token: token, IDs: ids}, nil
}

func (m *Memory) ConsumeReservation(a core.Association, token core.KeyID) ([]core.Delivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, exists := m.reservations[token]
	if !exists {
		return nil, core.ErrUnavailable
	}
	if r.association != a || r.pool != m.protection.Ref(a) {
		return nil, core.ErrUnauthorized
	}
	now := m.now()
	for _, id := range r.ids {
		e := m.keys[id]
		expire(e, now)
		if e.meta.Pool != r.pool || e.meta.MasterState != core.Reserved {
			return nil, core.ErrUnavailable
		}
		if m.policy(e, len(r.ids), now) != "" {
			return nil, core.ErrUnavailable
		}
	}
	out := make([]core.Delivery, 0, len(r.ids))
	for _, id := range r.ids {
		e := m.keys[id]
		out = append(out, core.Delivery{ID: id, Material: append([]byte(nil), e.master...)})
		clear(e.master)
		e.master = nil
		e.meta.MasterState = core.Consumed
		e.meta.SlaveState = core.Available
	}
	delete(m.reservations, token)
	return out, nil
}

func (m *Memory) ConsumePeerKeys(a core.Association, ids []core.KeyID) ([]core.Delivery, error) {
	if !a.Valid() || len(ids) < 1 || len(ids) > core.MaxBatch {
		return nil, core.ErrInvalid
	}
	seen := make(map[core.KeyID]bool, len(ids))
	for _, id := range ids {
		if !id.Valid() || seen[id] {
			return nil, core.ErrInvalid
		}
		seen[id] = true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for _, id := range ids {
		e, ok := m.keys[id]
		if !ok {
			return nil, core.ErrUnavailable
		}
		if e.meta.Association != a {
			return nil, core.ErrUnauthorized
		}
		expire(e, now)
		if e.meta.SlaveState != core.Available {
			return nil, core.ErrUnavailable
		}
		if m.policy(e, len(ids), now) != "" {
			return nil, core.ErrUnavailable
		}
	}
	out := make([]core.Delivery, 0, len(ids))
	for _, id := range ids {
		e := m.keys[id]
		out = append(out, core.Delivery{ID: id, Material: append([]byte(nil), e.slave...)})
		clear(e.slave)
		e.slave = nil
		e.meta.SlaveState = core.Consumed
	}
	return out, nil
}

func (m *Memory) InvalidateKey(id core.KeyID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.keys[id]
	if !ok {
		return core.ErrUnavailable
	}
	expire(e, m.now())
	if !e.meta.MasterState.Terminal() {
		e.meta.MasterState = core.Invalid
		clear(e.master)
		e.master = nil
	}
	if !e.meta.SlaveState.Terminal() {
		e.meta.SlaveState = core.Invalid
		clear(e.slave)
		e.slave = nil
	}
	return nil
}

func (m *Memory) Metadata(id core.KeyID) (core.Metadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.keys[id]
	if !ok {
		return core.Metadata{}, core.ErrUnavailable
	}
	expire(e, m.now())
	return e.meta, nil
}

func (m *Memory) Inventory(a core.Association) core.Inventory {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := core.Inventory{Capacity: m.capacity}
	now := m.now()
	for _, e := range m.keys {
		expire(e, now)
		if e.meta.Association == a && e.meta.MasterState == core.Available && m.policy(e, 1, now) == "" {
			result.Available++
		}
	}
	return result
}

func (m *Memory) policy(e *entry, n int, now time.Time) string {
	if reason := m.protection.Check(e.meta.Association, e.meta.ID, now); reason != "" {
		return reason
	}
	f := allocation.ProviderFacts(allocation.LocalFacts(e.meta.Source, e.meta.CreatedAt, e.meta.ExpiresAt, m.setup), m.protection, e.meta.ID, m.setup)
	return m.allocation.Check(e.meta.Association, n, f, now)
}
