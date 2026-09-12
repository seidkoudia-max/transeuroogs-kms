package etsi020

import (
	"encoding/json"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
)

// PoolExtension is an opt-in project mandatory extension. It is not an ETSI-
// assigned field and requires both KMSs to deploy this explicit project profile.
const PoolExtension = "E0_transeuroogs_pool_v1"

type PoolContext struct {
	Service string `json:"service_id"`
	Epoch   string `json:"service_epoch"`
	Purpose string `json:"purpose"`
}

func Context(p core.PoolRef) PoolContext { return PoolContext{p.Service, p.ServiceEpoch, p.Purpose} }
func PoolMandatory(p core.PoolRef) Extension {
	if p.Empty() {
		return nil
	}
	b, _ := json.Marshal(Context(p))
	return Extension{PoolExtension: b}
}
func MatchesPool(t Transfer, p core.PoolRef) bool {
	if p.Empty() {
		return len(t.Mandatory) == 0
	}
	b, ok := t.Mandatory[PoolExtension]
	if !ok || len(t.Mandatory) != 1 {
		return false
	}
	var got PoolContext
	if json.Unmarshal(b, &got) != nil {
		return false
	}
	want, _ := json.Marshal(got)
	// Exact encoding excludes duplicate/case-alias/unknown scope fields.
	return string(b) == string(want) && got == Context(p)
}
