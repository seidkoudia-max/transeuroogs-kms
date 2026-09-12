package ingest

import (
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/federation"
	"time"
)

// EvidenceProvider and CorrelatedProvider are project adapter contracts. Plain
// ETSI 014 has neither signed evidence nor an idempotent allocation/status API.
type EvidenceProvider interface {
	Evidence([]core.KeyID) (map[core.KeyID]string, error)
}
type CorrelatedProvider interface {
	AllocateRequest(core.KeyID, int) ([]core.Delivery, error)
	RetrieveRequest(core.KeyID, []core.KeyID) ([]core.Delivery, error)
	Outcome(core.KeyID) (string, error) // read-only; must never retrieve key bytes
}

func (r *Repository) allocate(q *request, n int) ([]core.Delivery, error) {
	if p, ok := r.provider.(CorrelatedProvider); ok {
		return p.AllocateRequest(q.Reference, n)
	}
	return r.provider.Allocate(n)
}
func (r *Repository) retrieve(q *request, ids []core.KeyID) ([]core.Delivery, error) {
	if p, ok := r.provider.(CorrelatedProvider); ok {
		return p.RetrieveRequest(q.Reference, ids)
	}
	return r.provider.Retrieve(ids)
}
func (r *Repository) collectEvidence(q *request) error {
	s := r.s.Protection
	if s == nil {
		return nil
	}
	p, _ := s.Pool(r.pair)
	if provider, ok := r.provider.(EvidenceProvider); ok {
		tokens, e := provider.Evidence(q.IDs)
		if e != nil {
			return e
		}
		for _, id := range q.IDs {
			token := tokens[id]
			if token == "" {
				if p.RequireEvidence {
					return core.ErrUnavailable
				}
				continue
			}
			v, e := s.Verify(p.Ref.ID, token, r.now())
			if e != nil || v.Key != id {
				return core.ErrInvalid
			}
			if e = s.PutEvidence(p.Ref.ID, token, r.now()); e != nil {
				return e
			}
			k := r.s.Keys[id]
			expiry := v.ExpiresAt.Add(-time.Duration(v.ClockUncertaintyMS) * time.Millisecond)
			if expiry.Before(k.Expires) {
				k.Expires = expiry
			}
		}
	}
	for _, id := range q.IDs {
		if s.Check(r.pair, id, r.now()) != "" {
			return core.ErrUnavailable
		}
	}
	return nil
}

var _ federation.Manager = (*Repository)(nil)

func (r *Repository) ProtectionView(pools []string, sae string) (federation.View, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.broken || r.s.Protection == nil {
		return federation.View{}, durable.ErrState
	}
	return federation.Clone(r.s.Protection.View(pools, sae)), nil
}
func (r *Repository) ApplyProtection(actor string, c federation.Command) (federation.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.broken || r.s.Protection == nil {
		return federation.Result{}, durable.ErrState
	}
	next := federation.Clone(r.s.Protection)
	before := next.Revision
	out, e := next.Apply(actor, c, r.now())
	if e != nil {
		return out, e
	}
	if next.Revision == before {
		return out, nil
	}
	if c.Operation == "invalidate" {
		for _, k := range r.s.Keys {
			if k.Pool.ID != c.Pool {
				continue
			}
			if k.State == core.Consumed {
				out.AlreadyDelivered++
			} else if !k.State.Terminal() {
				clear(k.Material)
				k.Material = nil
				k.State = core.Invalid
				out.Invalidated++
			}
		}
		out.RemoteStatus = "provider_action_needed"
	}
	next.Actions[len(next.Actions)-1] = out
	r.s.Protection = next
	if e = r.save(); e != nil {
		return federation.Result{}, e
	}
	return out, nil
}
func (r *Repository) keyMetadata(id core.KeyID) (core.Metadata, error) {
	k := r.s.Keys[id]
	if k == nil {
		return core.Metadata{}, core.ErrUnavailable
	}
	m := core.Metadata{ID: id, Pool: k.Pool, Association: r.pair, Source: r.cfg.URL, CreatedAt: k.Created, ExpiresAt: k.Expires, MasterState: core.Invalid, SlaveState: core.Invalid}
	if r.cfg.Role == "master" {
		m.MasterState = k.State
	} else {
		m.SlaveState = k.State
	}
	return m, nil
}
func (r *Repository) RecordReceipt(receipt federation.Receipt) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.broken || r.s.Protection == nil {
		return durable.ErrState
	}
	m, e := r.keyMetadata(receipt.Key)
	if e != nil {
		return e
	}
	if e = r.s.Protection.AddReceipt(receipt, m, r.now()); e != nil {
		return e
	}
	return r.save()
}
func (r *Repository) ImportEvidence(actor, pool, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.s.Protection
	if r.broken || s == nil {
		return durable.ErrState
	}
	if !s.Authorized(actor, pool, true) {
		return core.ErrUnauthorized
	}
	v, e := s.Verify(pool, token, r.now())
	if e != nil {
		return e
	}
	k := r.s.Keys[v.Key]
	if k == nil || k.Pool != v.Pool {
		return core.ErrUnavailable
	}
	if e = s.PutEvidence(pool, token, r.now()); e != nil {
		return e
	}
	expiry := v.ExpiresAt.Add(-time.Duration(v.ClockUncertaintyMS) * time.Millisecond)
	if expiry.Before(k.Expires) {
		k.Expires = expiry
	}
	return r.save()
}

type Pending struct {
	Reference core.KeyID   `json:"request_reference"`
	Pool      core.PoolRef `json:"binding"`
	Count     int          `json:"count"`
	KnownIDs  []core.KeyID `json:"known_key_ids"`
	Status    string       `json:"status"`
}

func (r *Repository) PendingRequests(actor, pool string) ([]Pending, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.broken || r.s.Protection == nil {
		return nil, durable.ErrState
	}
	if !r.s.Protection.Authorized(actor, pool, false) {
		return nil, core.ErrUnauthorized
	}
	out := []Pending{}
	for _, q := range r.s.Requests {
		if q.Pool.ID == pool && q.Status == "uncertain" {
			out = append(out, Pending{q.Reference, q.Pool, q.Count, append([]core.KeyID(nil), q.IDs...), q.Status})
		}
	}
	return out, nil
}
func (r *Repository) Reconcile(actor, pool string, id, reference core.KeyID) (federation.Reconciliation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.s.Protection
	if r.broken || s == nil {
		return federation.Reconciliation{}, durable.ErrState
	}
	if !s.Authorized(actor, pool, true) {
		return federation.Reconciliation{}, core.ErrUnauthorized
	}
	if !id.Valid() || !reference.Valid() {
		return federation.Reconciliation{}, core.ErrInvalid
	}
	if old, ok := s.Reconciliations[id]; ok {
		if old.Actor != actor || old.Pool != pool || old.Request != reference {
			return federation.Reconciliation{}, federation.ErrConflict
		}
		return old, nil
	}
	if len(s.Reconciliations) >= s.Config.MaxActions {
		return federation.Reconciliation{}, core.ErrCapacity
	}
	found := false
	for _, q := range r.s.Requests {
		if q.Reference == reference && q.Pool.ID == pool && q.Status == "uncertain" {
			found = true
		}
	}
	if !found {
		return federation.Reconciliation{}, core.ErrUnavailable
	}
	out := federation.Reconciliation{ID: id, Pool: pool, Request: reference, Actor: actor, Status: "query_pending", At: r.now()}
	s.Reconciliations[id] = out
	if e := r.save(); e != nil {
		return federation.Reconciliation{}, e
	}
	out.Status = "unsupported_by_provider"
	if p, ok := r.provider.(CorrelatedProvider); ok {
		status, e := p.Outcome(reference)
		out.Status = "unknown"
		if e == nil && (status == "consumed" || status == "not_consumed" || status == "unknown") {
			out.Status = status
		}
	}
	// Even a provider's "not_consumed" report is not permission to restore or
	// repeat an uncertain allocation. Recovery only adds evidence to the ledger.
	s.Reconciliations[id] = out
	if e := r.save(); e != nil {
		return federation.Reconciliation{}, e
	}
	return out, nil
}
