package relay

import (
	"bytes"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"testing"
)

func TestServiceDeleteVoidsRemoteOwnershipAndSurvivesRestart(t *testing.T) {
	n := setup(t, false)
	old := n.nodes["lu"]
	cfg := old.cfg
	old.Close()
	policy := testallocation.Setup(association)
	testallocation.Services(policy)
	disk := &testallocation.Disk{}
	e, err := OpenStore(cfg, []core.Association{association}, 1000, link{n, "lu"}, disk, nil, policy)
	if err != nil {
		t.Fatal(err)
	}
	n.nodes["lu"] = e
	e.retry = 0
	if _, err = e.ApplyCommand(testallocation.Actor, testallocation.Service(policy, 0, "application_create")); err != nil {
		t.Fatal(err)
	}
	keys := seed(t, e, 1)
	n.pump(5)
	res, err := e.ReserveKeys(association, 1)
	if err != nil {
		t.Fatal(err)
	}
	remove := testallocation.Service(policy, 1, "application_delete")
	if _, err = e.ApplyCommand(testallocation.Actor, remove); err != nil {
		t.Fatal(err)
	}
	record := e.s.Keys[keys[0].ID]
	if !record.Voiding || len(record.Material) != 0 || !record.VoidPending[record.Next] {
		t.Fatal("remote ownership not voided")
	}
	e.Close()
	e, err = OpenStore(cfg, []core.Association{association}, 1000, link{n, "lu"}, disk, bytes.Clone(disk.Raw), policy)
	if err != nil {
		t.Fatal(err)
	}
	n.nodes["lu"] = e
	e.retry = 0
	if _, err = e.ApplyCommand(testallocation.Actor, testallocation.Service(policy, 2, "application_create")); err != nil {
		t.Fatal(err)
	}
	if _, err = e.ConsumeReservation(association, res.Token); err == nil {
		t.Fatal("old relay reservation revived")
	}
	fresh := seed(t, e, 1)
	if _, err = e.ApplyCommand(testallocation.Actor, remove); err != nil {
		t.Fatal(err)
	}
	if e.s.Keys[fresh[0].ID].Voiding {
		t.Fatal("delete replay voided later key")
	}
	n.pump(5)
	for _, node := range n.nodes {
		if k := node.s.Keys[keys[0].ID]; k != nil && !k.Voiding {
			t.Fatal("void did not propagate")
		}
	}
}
