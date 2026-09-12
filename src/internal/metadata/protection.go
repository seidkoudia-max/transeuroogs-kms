package metadata

import (
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/federation"
)

type ProtectionRecord struct {
	Reference      string                     `json:"reference"`
	Association    core.Association           `json:"association"`
	Pool           core.PoolRef               `json:"binding"`
	Mapping        *federation.Pool           `json:"mapping,omitempty"`
	Action         *federation.Result         `json:"action,omitempty"`
	Receipt        *federation.Receipt        `json:"receipt,omitempty"`
	Reconciliation *federation.Reconciliation `json:"reconciliation,omitempty"`
}

func (r ProtectionRecord) valid() bool {
	if len(r.Reference) == 0 || len(r.Reference) > 256 || !r.Association.Valid() || !r.Pool.Valid() {
		return false
	}
	n := 0
	if r.Mapping != nil {
		n++
		if r.Mapping.Association != r.Association || r.Mapping.Ref != r.Pool {
			return false
		}
	}
	if r.Action != nil {
		n++
		if r.Action.Command.Pool != r.Pool.ID || !r.Action.Command.ID.Valid() || !r.Action.Command.Incident.Valid() || r.Action.Revision == 0 || r.Action.At.IsZero() {
			return false
		}
	}
	if r.Receipt != nil {
		n++
		if r.Receipt.Pool != r.Pool || r.Receipt.Association != r.Association || !r.Receipt.Key.Valid() || !r.Receipt.ID.Valid() || r.Receipt.At.IsZero() {
			return false
		}
	}
	if r.Reconciliation != nil {
		n++
		if r.Reconciliation.Pool != r.Pool.ID || !r.Reconciliation.ID.Valid() || !r.Reconciliation.Request.Valid() || r.Reconciliation.At.IsZero() {
			return false
		}
	}
	return n == 1
}

// ProjectProtection adds material-free registry/incident/receipt events to the
// same signed snapshot transaction as the underlying lifecycle change.
func ProjectProtection(p *Projection, s *federation.State) {
	p.Protection = map[string]ProtectionRecord{}
	if s == nil {
		return
	}
	for _, pool := range s.Config.Pools {
		id := "pool/" + pool.Ref.ID
		p.Protection[id] = ProtectionRecord{Reference: id, Association: pool.Association, Pool: pool.Ref, Mapping: &pool}
	}
	for _, a := range s.Actions {
		pool, _ := s.ByID(a.Command.Pool)
		id := "action/" + string(a.Command.ID)
		p.Protection[id] = ProtectionRecord{Reference: id, Association: pool.Association, Pool: pool.Ref, Action: &a}
	}
	for _, r := range s.Receipts {
		id := "receipt/" + string(r.ID)
		p.Protection[id] = ProtectionRecord{Reference: id, Association: r.Association, Pool: r.Pool, Receipt: &r}
	}
	for _, r := range s.Reconciliations {
		pool, _ := s.ByID(r.Pool)
		id := "reconciliation/" + string(r.ID)
		p.Protection[id] = ProtectionRecord{Reference: id, Association: pool.Association, Pool: pool.Ref, Reconciliation: &r}
	}
	for id, r := range p.Keys {
		if evidence, ok := s.Evidence[id]; ok {
			r.ProviderEvidence = &evidence
			r.SourceClass = evidence.Origin
			r.SourceEvidence = "verified_adapter_signature"
			r.GenerationTime = &evidence.GeneratedAt
		}
		p.Keys[id] = r
	}
}
