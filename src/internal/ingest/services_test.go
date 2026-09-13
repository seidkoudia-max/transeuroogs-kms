package ingest

import (
	"bytes"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"testing"
)

func TestServiceDeletionDoesNotRefetchBurnedProviderKeys(t *testing.T) {
	cfg := testallocation.Setup(pair)
	testallocation.Services(cfg)
	disk := &testallocation.Disk{}
	provider := &fakeProvider{}
	c := profile(t, "master")
	r, err := OpenStore(c, pair, 100, provider, disk, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.ReserveKeys(pair, 1); err == nil || provider.calls.Load() != 0 {
		t.Fatal("unregistered upstream consumption")
	}
	if _, err = r.ApplyCommand(testallocation.Actor, testallocation.Service(cfg, 0, "application_create")); err != nil {
		t.Fatal(err)
	}
	res, err := r.ReserveKeys(pair, 1)
	if err != nil {
		t.Fatal(err)
	}
	remove := testallocation.Service(cfg, 1, "application_delete")
	if _, err = r.ApplyCommand(testallocation.Actor, remove); err != nil {
		t.Fatal(err)
	}
	if r.s.Keys[res.IDs[0]].State != core.Invalid || len(r.s.Keys[res.IDs[0]].Material) != 0 {
		t.Fatal("provider material retained")
	}
	if _, err = r.ApplyCommand(testallocation.Actor, testallocation.Service(cfg, 2, "application_create")); err != nil {
		t.Fatal(err)
	}
	r.Close()
	r, err = OpenStore(c, pair, 100, provider, disk, bytes.Clone(disk.Raw), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err = r.ConsumeReservation(pair, res.Token); err == nil || provider.calls.Load() != 1 {
		t.Fatal("old reservation refetched")
	}
	fresh, err := r.ReserveKeys(pair, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.ApplyCommand(testallocation.Actor, remove); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ConsumeReservation(pair, fresh.Token); err != nil {
		t.Fatal("replay invalidated later registration")
	}
}
