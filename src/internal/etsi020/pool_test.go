package etsi020

import (
	"encoding/json"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"testing"
)

func TestMandatoryPoolContextCannotBeDroppedOrReinterpreted(t *testing.T) {
	p := core.PoolRef{ID: "LU/OGS/GR", RemoteID: "GR/OGS/LU", Revision: 1, Service: "LU-GR", ServiceEpoch: "epoch-1", Purpose: "tls"}
	tx := Transfer{Mandatory: PoolMandatory(p)}
	if !MatchesPool(tx, p) || MatchesPool(tx, core.PoolRef{}) || MatchesPool(Transfer{}, p) {
		t.Fatal("pool context downgrade accepted")
	}
	for _, mutate := range []func(*core.PoolRef){func(p *core.PoolRef) { p.Service = "LU-DE" }, func(p *core.PoolRef) { p.ServiceEpoch = "old" }, func(p *core.PoolRef) { p.Purpose = "link" }} {
		bad := p
		mutate(&bad)
		if MatchesPool(tx, bad) {
			t.Fatal("different service context accepted")
		}
	}
	other := p
	other.ID, other.RemoteID = p.RemoteID, p.ID
	other.Revision = 3
	if !MatchesPool(tx, other) {
		t.Fatal("corresponding local names incorrectly required to match")
	}
	tx.Mandatory[PoolExtension] = json.RawMessage(`{"service_id":"LU-GR","service_id":"LU-DE","service_epoch":"epoch-1","purpose":"tls"}`)
	if MatchesPool(tx, p) {
		t.Fatal("duplicate scope accepted")
	}
}
