package core

// PoolRef is local immutable delivery context, not an ETSI 014 wire field.
// Service and Purpose are shared application context; local pool names may differ.
type PoolRef struct {
	ServiceEpoch string `json:"service_epoch"`
	ID           string `json:"pool_id"`
	Revision     uint64 `json:"binding_revision"`
	RemoteID     string `json:"remote_pool_id"`
	Service      string `json:"service_id"`
	Purpose      string `json:"purpose"`
}

func (p PoolRef) Valid() bool {
	return validName(p.ServiceEpoch) && validName(p.ID) && p.Revision > 0 && validName(p.RemoteID) && validName(p.Service) && validName(p.Purpose)
}

func (p PoolRef) Empty() bool { return p == (PoolRef{}) }
