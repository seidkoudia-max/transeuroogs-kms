package storage

import (
	"bytes"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"sync"
	"testing"
	"time"
)

func TestApplicationDeleteBurnsReservationsAndReplayPreservesNewKeys(t *testing.T) {
	a := core.Association{Master: "A", Slave: "B"}
	cfg := testallocation.Setup(a)
	testallocation.Services(cfg)
	disk := &testallocation.Disk{}
	r, err := OpenPersistent(10, "test", disk, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r.memory.now = func() time.Time { return now }
	if _, err = r.ApplyCommand(testallocation.Actor, testallocation.Service(cfg, 0, "application_create")); err != nil {
		t.Fatal(err)
	}
	add := func() core.KeyID {
		id := core.NewID()
		if e := r.StoreKey(core.Key{ID: id, Association: a, Material: bytes.Repeat([]byte{7}, 32), Source: "synthetic-qkd", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); e != nil {
			t.Fatal(e)
		}
		return id
	}
	first := add()
	res, err := r.ReserveKeys(a, 1)
	if err != nil {
		t.Fatal(err)
	}
	remove := testallocation.Service(cfg, 1, "application_delete")
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := r.ApplyCommand(testallocation.Actor, remove); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if _, err = r.ConsumeReservation(a, res.Token); err == nil {
		t.Fatal("deleted app delivered")
	}
	if _, err = r.ApplyCommand(testallocation.Actor, testallocation.Service(cfg, 2, "application_create")); err != nil {
		t.Fatal(err)
	}
	second := add()
	if _, err = r.ApplyCommand(testallocation.Actor, remove); err != nil {
		t.Fatal(err)
	}
	if m, _ := r.Metadata(first); m.MasterState != core.Invalid {
		t.Fatal("old key returned")
	}
	if m, _ := r.Metadata(second); m.MasterState != core.Available {
		t.Fatal("replay burned later key")
	}
	r.Close()
	r, err = OpenPersistent(10, "test", disk, bytes.Clone(disk.Raw), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err = r.ConsumeReservation(a, res.Token); err == nil {
		t.Fatal("restarted old reservation")
	}
	res, err = r.ReserveKeys(a, 1)
	if err != nil || res.IDs[0] != second {
		t.Fatal("new registration unusable", err)
	}
	disk.Fail = true
	if _, err = r.ApplyCommand(testallocation.Actor, testallocation.Service(cfg, 3, "application_delete")); err == nil {
		t.Fatal("ambiguous deletion acknowledged")
	}
	if _, err = r.ConsumeReservation(a, res.Token); err == nil {
		t.Fatal("failed snapshot allowed delivery")
	}
}
