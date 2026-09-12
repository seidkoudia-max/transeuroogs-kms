package storage

import (
	"bytes"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/federation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testfederation"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPoolIsolationIncidentRaceRestartAndNoResurrection(t *testing.T) {
	a, b := core.Association{Master: "A", Slave: "B"}, core.Association{Master: "A", Slave: "C"}
	c := testfederation.Config(a, b)
	disk := &testallocation.Disk{}
	r, e := OpenPersistentControlled(10, "test", disk, nil, c)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	ids := []core.KeyID{core.NewID(), core.NewID()}
	for i, pair := range []core.Association{a, b} {
		if e = r.StoreKey(core.Key{ID: ids[i], Association: pair, Material: bytes.Repeat([]byte{byte(i + 1)}, 32), Source: "synthetic-qkd", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); e != nil {
			t.Fatal(e)
		}
	}
	res, e := r.ReserveKeys(a, 1)
	if e != nil || res.Pool != c.Pools[0].Ref {
		t.Fatal("reservation unbound", e)
	}
	if _, e = r.ConsumePeerKeys(b, res.IDs); e != core.ErrUnauthorized {
		t.Fatal("cross-pool by-ID accepted", e)
	}
	cmd := testfederation.Command(c, 0, core.NewID(), "hold")
	if _, e = r.ApplyProtection(testfederation.Actor, cmd); e != nil {
		t.Fatal(e)
	}
	var deliveries atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if d, e := r.ConsumeReservation(a, res.Token); e == nil {
				deliveries.Add(1)
				for _, k := range d {
					clear(k.Material)
				}
			}
		})
	}
	wg.Wait()
	if deliveries.Load() != 0 {
		t.Fatal("reserved material escaped committed hold")
	}
	if r.Inventory(b).Available != 1 {
		t.Fatal("unrelated pool held")
	}
	r.Close()
	r, e = OpenPersistentControlled(10, "test", disk, bytes.Clone(disk.Raw), c)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if _, e = r.ConsumeReservation(a, res.Token); e == nil {
		t.Fatal("hold lost across restart")
	}
	inv := testfederation.Command(c, 1, cmd.Incident, "invalidate")
	out, e := r.ApplyProtection(testfederation.Actor, inv)
	if e != nil || out.Invalidated != 2 || out.AlreadyDelivered != 0 {
		t.Fatal("invalidation counts", e)
	}
	if _, e = r.ApplyProtection(testfederation.Actor, testfederation.Command(c, 2, cmd.Incident, "release")); e != nil {
		t.Fatal(e)
	}
	if _, e = r.ConsumeReservation(a, res.Token); e == nil || r.Inventory(a).Available != 0 {
		t.Fatal("release revived invalidated key")
	}
	if _, e = r.ApplyProtection(testfederation.Actor, inv); e != nil {
		t.Fatal("exact replay", e)
	}
	disk.Fail = true
	if _, e = r.ApplyProtection(testfederation.Actor, testfederation.Command(c, 3, core.NewID(), "hold")); e == nil {
		t.Fatal("failed commit acknowledged")
	}
	if _, e = r.ReserveKeys(b, 1); e == nil {
		t.Fatal("poisoned repository delivered")
	}
}

func TestProviderEvidenceAndAuthenticatedReceipts(t *testing.T) {
	a := core.Association{Master: "A", Slave: "B"}
	c := testfederation.Config(a)
	now := time.Now().UTC()
	k, e := testfederation.Signing(c, now)
	if e != nil {
		t.Fatal(e)
	}
	c.Pools[0].RequireEvidence = true
	r, e := OpenPersistentControlled(10, "test", &testallocation.Disk{}, nil, c)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	id := core.NewID()
	if e = r.StoreKey(core.Key{ID: id, Association: a, Material: bytes.Repeat([]byte{1}, 32), Source: "synthetic-qkd", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); e != nil {
		t.Fatal(e)
	}
	if _, e = r.ReserveKeys(a, 1); e == nil {
		t.Fatal("missing provider evidence accepted")
	}
	proof, _ := federation.SignEvidence(testfederation.Evidence(c.Pools[0], id, now), k)
	if e = r.ImportEvidence(testfederation.Actor, c.Pools[0].Ref.ID, proof); e != nil {
		t.Fatal(e)
	}
	res, e := r.ReserveKeys(a, 1)
	if e != nil {
		t.Fatal(e)
	}
	receipt := federation.Receipt{ID: core.NewID(), Session: core.NewID(), Key: id, Pool: c.Pools[0].Ref, Association: a, SAE: "A", Status: "confirmed"}
	if e = r.RecordReceipt(receipt); e == nil {
		t.Fatal("undelivered key confirmation accepted")
	}
	d, e := r.ConsumeReservation(a, res.Token)
	if e != nil {
		t.Fatal(e)
	}
	for _, k := range d {
		clear(k.Material)
	}
	for range 2 {
		if e = r.RecordReceipt(receipt); e != nil {
			t.Fatal(e)
		}
	}
	bad := receipt
	bad.ID = core.NewID()
	bad.Session = core.NewID()
	if e = r.RecordReceipt(bad); e == nil {
		t.Fatal("same key assigned to new session")
	}
	out, e := r.ApplyProtection(testfederation.Actor, testfederation.Command(c, 0, core.NewID(), "invalidate"))
	if e != nil || out.AlreadyDelivered != 1 || out.Invalidated != 1 {
		t.Fatal("delivered bytes falsely revoked", e)
	}
	view, e := r.ProtectionView([]string{c.Pools[0].Ref.ID}, "A")
	if e != nil || len(view.Receipts) != 1 {
		t.Fatal("receipt missing", e)
	}
}
