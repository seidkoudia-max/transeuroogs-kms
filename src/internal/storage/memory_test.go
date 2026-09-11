package storage

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
)

var pair = core.Association{Master: "SAE-LU", Slave: "SAE-GR"}

func fixture(t *testing.T, capacity int) (*Memory, *time.Time) {
	t.Helper()
	now := time.Now()
	m, err := NewMemory(capacity, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return m, &now
}

func put(t *testing.T, m *Memory, now time.Time, a core.Association) core.Key {
	t.Helper()
	k := core.Key{ID: core.NewID(), Material: bytes.Repeat([]byte{42}, 32), Association: a, Source: "synthetic-test", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := m.StoreKey(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func reserve(t *testing.T, m *Memory, n int) core.Reservation {
	t.Helper()
	r, err := m.ReserveKeys(pair, n)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSingleDeliveryAndTombstone(t *testing.T) {
	m, now := fixture(t, 2)
	k := put(t, m, *now, pair)
	k.Material[0] = 99 // Ingestion must own its copy.
	if _, err := m.ConsumePeerKeys(pair, []core.KeyID{k.ID}); !errors.Is(err, core.ErrUnavailable) {
		t.Fatal("premature slave delivery")
	}
	r := reserve(t, m, 1)
	r.IDs[0] = core.NewID() // Reservation membership is owned by the repository.
	if _, err := m.ConsumeReservation(core.Association{Master: "OTHER", Slave: "SAE-GR"}, r.Token); !errors.Is(err, core.ErrUnauthorized) {
		t.Fatal("wrong owner consumed")
	}
	master, err := m.ConsumeReservation(pair, r.Token)
	if err != nil {
		t.Fatal(err)
	}
	if master[0].ID != k.ID || master[0].Material[0] != 42 {
		t.Fatal("aliased ingestion/reservation")
	}
	master[0].Material[0] = 33
	slave, err := m.ConsumePeerKeys(pair, []core.KeyID{k.ID})
	if err != nil {
		t.Fatal(err)
	}
	if slave[0].Material[0] != 42 {
		t.Fatal("aliased delivery")
	}
	if _, err := m.ConsumeReservation(pair, r.Token); !errors.Is(err, core.ErrUnavailable) {
		t.Fatal("token replay succeeded")
	}
	if _, err := m.ConsumePeerKeys(pair, []core.KeyID{k.ID}); !errors.Is(err, core.ErrUnavailable) {
		t.Fatal("slave replay succeeded")
	}
	if err := m.StoreKey(k); !errors.Is(err, core.ErrDuplicate) {
		t.Fatal("terminal ID reused")
	}
	if err := m.InvalidateKey(k.ID); err != nil {
		t.Fatal(err)
	}
	meta, _ := m.Metadata(k.ID)
	if meta.MasterState != core.Consumed || meta.SlaveState != core.Consumed {
		t.Fatal("terminal states changed")
	}
	if m.keys[k.ID].master != nil || m.keys[k.ID].slave != nil {
		t.Fatal("material retained in terminal records")
	}
}

func TestBatchAtomicityAndAssociation(t *testing.T) {
	m, now := fixture(t, 5)
	k1 := put(t, m, *now, pair)
	k2 := put(t, m, *now, pair)
	if _, err := m.ReserveKeys(pair, 3); !errors.Is(err, core.ErrUnavailable) || m.Inventory(pair).Available != 2 {
		t.Fatal("partial reservation")
	}
	r := reserve(t, m, 2)
	if _, err := m.ConsumeReservation(pair, r.Token); err != nil {
		t.Fatal(err)
	}
	for name, ids := range map[string][]core.KeyID{
		"missing": {k1.ID, core.NewID()}, "duplicate": {k1.ID, k1.ID}, "invalid": {k1.ID, "bad"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := m.ConsumePeerKeys(pair, ids); err == nil {
				t.Fatal("invalid batch accepted")
			}
			meta, _ := m.Metadata(k1.ID)
			if meta.SlaveState != core.Available {
				t.Fatal("partial batch delivery")
			}
		})
	}
	if _, err := m.ConsumePeerKeys(core.Association{Master: "SAE-LU", Slave: "OTHER"}, []core.KeyID{k1.ID}); !errors.Is(err, core.ErrUnauthorized) {
		t.Fatal("unauthorized delivery")
	}
	if _, err := m.ConsumePeerKeys(pair, []core.KeyID{k1.ID, k2.ID}); err != nil {
		t.Fatal(err)
	}
}

func TestExpiryAndInvalidation(t *testing.T) {
	for _, mode := range []string{"expiry", "invalidate"} {
		t.Run(mode, func(t *testing.T) {
			m, now := fixture(t, 4)
			first := put(t, m, *now, pair)
			second := put(t, m, *now, pair)
			r := reserve(t, m, 2)
			if mode == "expiry" {
				*now = now.Add(time.Hour)
			} else {
				if err := m.InvalidateKey(second.ID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := m.ConsumeReservation(pair, r.Token); !errors.Is(err, core.ErrUnavailable) {
				t.Fatal("invalid batch consumed")
			}
			meta, _ := m.Metadata(first.ID)
			if meta.MasterState == core.Consumed {
				t.Fatal("partial master consumption")
			}
			if _, err := m.ConsumePeerKeys(pair, []core.KeyID{second.ID}); err == nil {
				t.Fatal("expired/invalid slave delivered")
			}
			if m.keys[second.ID].master != nil || m.keys[second.ID].slave != nil {
				t.Fatal("invalid material retained")
			}
		})
	}
}

func TestSlaveExpiryAfterMasterDelivery(t *testing.T) {
	m, now := fixture(t, 1)
	k := put(t, m, *now, pair)
	r := reserve(t, m, 1)
	if _, err := m.ConsumeReservation(pair, r.Token); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Hour)
	if _, err := m.ConsumePeerKeys(pair, []core.KeyID{k.ID}); err == nil {
		t.Fatal("expired slave delivered")
	}
	meta, _ := m.Metadata(k.ID)
	if meta.MasterState != core.Consumed || meta.SlaveState != core.Expired {
		t.Fatal("incorrect recipient expiry")
	}
}

func TestCapacityAndValidation(t *testing.T) {
	m, now := fixture(t, 1)
	k := put(t, m, *now, pair)
	if err := m.StoreKey(k); !errors.Is(err, core.ErrDuplicate) {
		t.Fatal(err)
	}
	k.ID = core.NewID()
	if err := m.StoreKey(k); !errors.Is(err, core.ErrCapacity) {
		t.Fatal(err)
	}
	for _, n := range []int{-1, 0, 129} {
		if _, err := m.ReserveKeys(pair, n); !errors.Is(err, core.ErrInvalid) {
			t.Fatal("invalid count accepted")
		}
	}
	if _, err := NewMemory(0, nil); err == nil {
		t.Fatal("zero capacity accepted")
	}
	if got := m.Inventory(core.Association{Master: "OTHER", Slave: "SAE-GR"}).Available; got != 0 {
		t.Fatal("inventory crossed association")
	}
}

func TestConcurrentAllocationNoReuse(t *testing.T) {
	m, now := fixture(t, 1000)
	for range 1000 {
		put(t, m, *now, pair)
	}
	ids := make(chan core.KeyID, 1000)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for {
				r, err := m.ReserveKeys(pair, 1)
				if errors.Is(err, core.ErrUnavailable) {
					return
				}
				if err != nil {
					t.Error(err)
					return
				}
				keys, err := m.ConsumeReservation(pair, r.Token)
				if err != nil {
					t.Error(err)
					return
				}
				peer, err := m.ConsumePeerKeys(pair, []core.KeyID{keys[0].ID})
				if err != nil {
					t.Error(err)
					return
				}
				if !bytes.Equal(keys[0].Material, peer[0].Material) {
					t.Error("mismatched material")
				}
				ids <- keys[0].ID
			}
		})
	}
	wg.Wait()
	close(ids)
	seen := map[core.KeyID]bool{}
	for id := range ids {
		if seen[id] {
			t.Fatal("key reused")
		}
		seen[id] = true
	}
	if len(seen) != 1000 || m.Inventory(pair).Available != 0 {
		t.Fatal("lost keys or nonempty pool")
	}
}

func TestConcurrentSlaveReplay(t *testing.T) {
	m, now := fixture(t, 1)
	k := put(t, m, *now, pair)
	r := reserve(t, m, 1)
	if _, err := m.ConsumeReservation(pair, r.Token); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 20)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { _, err := m.ConsumePeerKeys(pair, []core.KeyID{k.ID}); results <- err })
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("got %d successful deliveries", successes)
	}
}
