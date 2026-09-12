// Package ingest owns local delivery state for the segmented upstream service.
// The provider owns paired-key establishment; no cross-site key transport occurs here.
package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sync"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/upstream"
)

type Provider interface {
	Allocate(int) ([]core.Delivery, error)
	Retrieve([]core.KeyID) ([]core.Delivery, error)
	Inventory() (core.Inventory, error)
}
type key struct {
	ID       core.KeyID
	Material []byte
	State    core.State
	Created  time.Time
	Expires  time.Time
}
type request struct {
	IDs     []core.KeyID
	Count   int
	Status  string
	Started time.Time
	Expires time.Time
}
type state struct {
	Allocation *allocation.State `json:",omitempty"`
	Version    int
	Binding    string
	Attempts   int
	Requests   map[core.KeyID]*request
	Keys       map[core.KeyID]*key
}
type Repository struct {
	setup    *allocation.Setup
	mu       sync.Mutex
	cfg      upstream.Config
	pair     core.Association
	capacity int
	provider Provider
	journal  durable.Store
	s        state
	broken   bool
	now      func() time.Time
}

var _ core.Repository = (*Repository)(nil)

func Open(c upstream.Config, a core.Association, capacity int, p Provider) (*Repository, error) {
	j, raw, err := durable.Open(c.StateDir, "transeuroogs-segmented-ingestion-v1")
	if err != nil {
		return nil, err
	}
	return OpenStore(c, a, capacity, p, j, raw)
}

// OpenStore takes ownership of a persistence implementation and recovered state.
func OpenStore(c upstream.Config, a core.Association, capacity int, p Provider, j durable.Store, raw []byte, options ...*allocation.Setup) (*Repository, error) {
	defer clear(raw)
	success := false
	defer func() {
		if !success && j != nil {
			j.Close()
		}
	}()
	if c.Validate() != nil || !a.Valid() || capacity < 1 || capacity > 100000 || p == nil || j == nil || !durable.PlainSnapshot(raw) || len(options) > 1 {
		return nil, core.ErrInvalid
	}
	binding, _ := json.Marshal(struct {
		Config   upstream.Config
		Pair     core.Association
		Capacity int
	}{c, a, capacity})
	digest := sha256.Sum256(binding)
	r := &Repository{cfg: c, pair: a, capacity: capacity, provider: p, now: time.Now}
	r.setup = allocation.Select(options)
	r.s = state{Version: 1, Binding: hex.EncodeToString(digest[:]), Requests: map[core.KeyID]*request{}, Keys: map[core.KeyID]*key{}}
	r.journal = j
	var err error
	if raw != nil {
		var s state
		if json.Unmarshal(raw, &s) != nil || s.Version != 1 || s.Binding != r.s.Binding || s.Requests == nil || s.Keys == nil || s.Attempts < 0 || s.Attempts > capacity {
			j.Close()
			return nil, durable.ErrState
		}
		r.s = s
		for _, q := range r.s.Requests {
			if q == nil {
				r.Close()
				return nil, durable.ErrState
			}
			if q.Status == "pending" {
				q.Status = "uncertain"
				for _, id := range q.IDs {
					if k := r.s.Keys[id]; k != nil {
						clear(k.Material)
						k.Material = nil
						k.State = core.Invalid
					}
				}
			}
		}
		for _, k := range r.s.Keys {
			if k == nil {
				r.Close()
				return nil, durable.ErrState
			}
		}
	}
	r.s.Allocation, err = allocation.Open(r.setup, r.s.Allocation, raw != nil)
	if err != nil {
		r.Close()
		return nil, durable.ErrState
	}
	if err = r.expire(); err == nil {
		err = r.save()
	}
	if err != nil {
		r.Close()
		return nil, err
	}
	success = true
	return r, nil
}

// Callers hold mu. Any uncertain persistence error disables all further delivery.
func (r *Repository) save() error {
	data, err := json.Marshal(r.s)
	defer clear(data)
	if err == nil {
		err = r.journal.Save(data)
	}
	if err != nil {
		r.broken = true
		return durable.ErrState
	}
	return nil
}
func (r *Repository) expire() error {
	changed := false
	for _, k := range r.s.Keys {
		if !k.State.Terminal() && !r.now().Before(k.Expires) {
			clear(k.Material)
			k.Material = nil
			k.State = core.Expired
			changed = true
		}
	}
	if changed {
		return r.save()
	}
	return nil
}
func (r *Repository) check(a core.Association, role string) error {
	if r.broken {
		return durable.ErrState
	}
	if a != r.pair || r.cfg.Role != role {
		return core.ErrUnauthorized
	}
	return r.expire()
}
func (r *Repository) begin(n int, ids []core.KeyID) (core.KeyID, *request, error) {
	if n < 1 || n > core.MaxBatch {
		return "", nil, core.ErrInvalid
	}
	if r.s.Attempts+n > r.capacity {
		return "", nil, core.ErrCapacity
	}
	token := core.NewID()
	for r.s.Requests[token] != nil {
		token = core.NewID()
	}
	now := r.now()
	q := &request{IDs: slices.Clone(ids), Count: n, Status: "pending", Started: now, Expires: now.Add(time.Duration(r.cfg.LifetimeSeconds) * time.Second)}
	r.s.Requests[token] = q
	r.s.Attempts += n
	for _, id := range ids {
		r.s.Keys[id] = &key{ID: id, State: core.Reserved, Created: now, Expires: q.Expires}
	}
	if err := r.save(); err != nil {
		return "", nil, err
	}
	return token, q, nil
}
func wipe(keys []core.Delivery) {
	for _, k := range keys {
		clear(k.Material)
	}
}
func (r *Repository) uncertain(q *request) error {
	q.Status = "uncertain"
	for _, id := range q.IDs {
		if k := r.s.Keys[id]; k != nil {
			clear(k.Material)
			k.Material = nil
			k.State = core.Invalid
		}
	}
	if err := r.save(); err != nil {
		return err
	}
	return core.ErrUnavailable
}

// Validate provider output again at the persistence boundary, including exact batch membership.
func (r *Repository) validate(q *request, keys []core.Delivery, slave bool) bool {
	if len(keys) != q.Count || !r.now().Before(q.Expires) {
		return false
	}
	seen := map[core.KeyID]bool{}
	for _, k := range keys {
		if !k.ID.Valid() || len(k.Material) != core.KeyBits/8 || seen[k.ID] {
			return false
		}
		seen[k.ID] = true
		if slave {
			if !slices.Contains(q.IDs, k.ID) {
				return false
			}
		} else if r.s.Keys[k.ID] != nil {
			return false
		}
	}
	return true
}

// External injection would bypass provider binding and is deliberately unsupported.
func (r *Repository) StoreKey(core.Key) error { return core.ErrUnauthorized }

func (r *Repository) ReserveKeys(a core.Association, n int) (core.Reservation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.check(a, "master"); err != nil {
		return core.Reservation{}, err
	}
	if r.policy(n, r.now(), r.now().Add(time.Duration(r.cfg.LifetimeSeconds)*time.Second)) != "" {
		return core.Reservation{}, core.ErrUnavailable
	}
	token, q, err := r.begin(n, nil)
	if err != nil {
		return core.Reservation{}, err
	}
	keys, err := r.provider.Allocate(n)
	defer wipe(keys)
	if err != nil || !r.validate(q, keys, false) {
		return core.Reservation{}, r.uncertain(q)
	}
	for _, k := range keys {
		q.IDs = append(q.IDs, k.ID)
		r.s.Keys[k.ID] = &key{ID: k.ID, Material: slices.Clone(k.Material), State: core.Reserved, Created: q.Started, Expires: q.Expires}
	}
	q.Status = "stored"
	if r.policy(n, q.Started, q.Expires) != "" {
		return core.Reservation{}, r.uncertain(q)
	}
	if err := r.save(); err != nil {
		return core.Reservation{}, err
	}
	return core.Reservation{Token: token, IDs: slices.Clone(q.IDs)}, nil
}

func (r *Repository) ConsumeReservation(a core.Association, token core.KeyID) ([]core.Delivery, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.check(a, "master"); err != nil {
		return nil, err
	}
	q := r.s.Requests[token]
	if q == nil || q.Status != "stored" || !r.now().Before(q.Expires) {
		return nil, core.ErrUnavailable
	}
	if r.policy(q.Count, q.Started, q.Expires) != "" {
		return nil, core.ErrUnavailable
	}
	for _, id := range q.IDs {
		k := r.s.Keys[id]
		if k == nil || k.State != core.Reserved || len(k.Material) != core.KeyBits/8 {
			return nil, core.ErrUnavailable
		}
	}
	out := make([]core.Delivery, 0, q.Count)
	for _, id := range q.IDs {
		k := r.s.Keys[id]
		out = append(out, core.Delivery{ID: id, Material: slices.Clone(k.Material)})
		clear(k.Material)
		k.Material = nil
		k.State = core.Consumed
	}
	q.Status = "consumed"
	if err := r.save(); err != nil {
		wipe(out)
		return nil, err
	}
	return out, nil
}

func (r *Repository) ConsumePeerKeys(a core.Association, ids []core.KeyID) ([]core.Delivery, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.check(a, "slave"); err != nil {
		return nil, err
	}
	if len(ids) < 1 || len(ids) > core.MaxBatch {
		return nil, core.ErrInvalid
	}
	seen := map[core.KeyID]bool{}
	for _, id := range ids {
		if !id.Valid() || seen[id] {
			return nil, core.ErrInvalid
		}
		seen[id] = true
		if r.s.Keys[id] != nil {
			return nil, core.ErrUnavailable
		}
	}
	if r.policy(len(ids), r.now(), r.now().Add(time.Duration(r.cfg.LifetimeSeconds)*time.Second)) != "" {
		return nil, core.ErrUnavailable
	}
	_, q, err := r.begin(len(ids), ids)
	if err != nil {
		return nil, err
	}
	keys, err := r.provider.Retrieve(slices.Clone(ids))
	defer wipe(keys)
	if err != nil || !r.validate(q, keys, true) {
		return nil, r.uncertain(q)
	}
	if r.policy(len(ids), q.Started, q.Expires) != "" {
		return nil, r.uncertain(q)
	}
	byID := map[core.KeyID][]byte{}
	for _, k := range keys {
		byID[k.ID] = k.Material
	}
	out := make([]core.Delivery, 0, len(ids))
	for _, id := range ids {
		out = append(out, core.Delivery{ID: id, Material: slices.Clone(byID[id])})
		r.s.Keys[id].State = core.Consumed
	}
	q.Status = "consumed"
	if err := r.save(); err != nil {
		wipe(out)
		return nil, err
	}
	return out, nil
}

func (r *Repository) InvalidateKey(id core.KeyID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.broken {
		return durable.ErrState
	}
	k := r.s.Keys[id]
	if k == nil {
		return core.ErrUnavailable
	}
	if !k.State.Terminal() {
		clear(k.Material)
		k.Material = nil
		k.State = core.Invalid
		return r.save()
	}
	return nil
}
func (r *Repository) Metadata(id core.KeyID) (core.Metadata, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.broken {
		return core.Metadata{}, durable.ErrState
	}
	if err := r.expire(); err != nil {
		return core.Metadata{}, err
	}
	k := r.s.Keys[id]
	if k == nil {
		return core.Metadata{}, core.ErrUnavailable
	}
	m := core.Metadata{ID: id, Association: r.pair, Source: r.cfg.URL, CreatedAt: k.Created, ExpiresAt: k.Expires, MasterState: core.Invalid, SlaveState: core.Invalid}
	if r.cfg.Role == "master" {
		m.MasterState = k.State
	} else {
		m.SlaveState = k.State
	}
	return m, nil
}
func (r *Repository) Inventory(a core.Association) core.Inventory {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := core.Inventory{Capacity: r.capacity}
	if r.check(a, "master") != nil {
		return out
	}
	if r.policy(1, r.now(), r.now().Add(time.Duration(r.cfg.LifetimeSeconds)*time.Second)) != "" {
		return out
	}
	upstream, err := r.provider.Inventory()
	if err == nil && upstream.Available >= 0 {
		out.Available = min(upstream.Available, r.capacity-r.s.Attempts)
	}
	return out
}
func (r *Repository) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.mu.Lock()
			if !r.broken {
				_ = r.expire()
			}
			r.mu.Unlock()
		}
	}
}
func (r *Repository) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.broken = true
	for _, k := range r.s.Keys {
		if k != nil {
			clear(k.Material)
			k.Material = nil
		}
	}
	if r.journal != nil {
		r.journal.Close()
	}
}
