package storage

import (
	"bytes"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPolicyAtomicDeliveryRestartAndCommitFailure(t *testing.T) {
	a := core.Association{Master: "A", Slave: "B"}
	setup := testallocation.Setup(a)
	disk := &testallocation.Disk{}
	r, err := OpenPersistent(10, "test", disk, nil, setup)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r.memory.now = func() time.Time { return now }
	for range 3 {
		if err = r.StoreKey(core.Key{ID: core.NewID(), Association: a, Material: bytes.Repeat([]byte{1}, 32), Source: "synthetic-qkd", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := r.ReserveKeys(a, 2)
	if err != nil {
		t.Fatal(err)
	}
	rule := testallocation.Rule()
	rule.Paused = true
	cmd := testallocation.Command(a, 0, rule)
	if _, err = r.ApplyCommand("urn:test:app", cmd); err != core.ErrUnauthorized {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := r.ApplyCommand(testallocation.Actor, cmd); e == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 16 {
		t.Fatal("exact concurrent replay failed")
	}
	if d, e := r.ConsumeReservation(a, res.Token); e == nil || len(d) != 0 {
		t.Fatal("reserved batch escaped pause")
	}
	r.Close()
	r, err = OpenPersistent(10, "test", disk, bytes.Clone(disk.Raw), setup)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err = r.ReserveKeys(a, 1); err == nil {
		t.Fatal("pause lost on restart")
	}
	rule.Paused = false
	rule.MaxKeysPerRequest = 1
	if _, err = r.ApplyCommand(testallocation.Actor, testallocation.Command(a, 1, rule)); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ConsumeReservation(a, res.Token); err == nil {
		t.Fatal("batch limit bypass")
	}
	rule.MaxKeysPerRequest = 2
	if _, err = r.ApplyCommand(testallocation.Actor, testallocation.Command(a, 2, rule)); err != nil {
		t.Fatal(err)
	}
	keys, err := r.ConsumeReservation(a, res.Token)
	if err != nil || len(keys) != 2 {
		t.Fatal(err)
	}
	for _, k := range keys {
		clear(k.Material)
	}
	if _, err = r.ConsumeReservation(a, res.Token); err == nil {
		t.Fatal("burned keys returned")
	}
	rule.Paused = true
	if _, err = r.ApplyCommand(testallocation.Actor, testallocation.Command(a, 3, rule)); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ConsumePeerKeys(a, res.IDs); err == nil {
		t.Fatal("peer bypassed pause")
	}
	view, err := r.ManagementView([]core.Association{a})
	if err != nil || view.Apps[0].Counts.Eligible != 0 || view.Apps[0].Counts.Delivered != 2 {
		t.Fatal("wrong counters", err)
	}
	disk.Fail = true
	rule.Paused = false
	cmd = testallocation.Command(a, 4, rule)
	if _, err = r.ApplyCommand(testallocation.Actor, cmd); err == nil {
		t.Fatal("ambiguous command acknowledged")
	}
	if d, e := r.ConsumePeerKeys(a, res.IDs); e == nil || len(d) > 0 {
		t.Fatal("failed store still delivers")
	}
	r.Close()
	disk.Fail = false
	r, err = OpenPersistent(10, "test", disk, bytes.Clone(disk.Raw), setup)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if result, e := r.ApplyCommand(testallocation.Actor, cmd); e != nil || result.Revision != 5 {
		t.Fatal("recovery replay", e)
	}
}
func TestFreshnessRecheckedForWholeReservation(t *testing.T) {
	a := core.Association{Master: "A", Slave: "B"}
	setup := testallocation.Setup(a)
	setup.Config.Apps[0].Rule.MaxGenerationAgeSeconds = 1
	d := &testallocation.Disk{}
	r, err := OpenPersistent(10, "test", d, nil, setup)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	now := time.Now()
	r.memory.now = func() time.Time { return now }
	if err = r.StoreKey(core.Key{ID: core.NewID(), Association: a, Material: bytes.Repeat([]byte{1}, 32), Source: "synthetic-qkd", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	res, err := r.ReserveKeys(a, 1)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, err = r.ConsumeReservation(a, res.Token); err == nil {
		t.Fatal("stale reserved key delivered")
	}
	// Last accepted local rule remains effective without any controller calls.
	if m, _ := r.Metadata(res.IDs[0]); m.MasterState != core.Reserved {
		t.Fatal("denial burned or returned reservation")
	}
	var _ allocation.Manager = r
}
