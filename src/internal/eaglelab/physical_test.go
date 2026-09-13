package eaglelab

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/storage"
)

func validPermit() PhysicalPermit {
	return PhysicalPermit{Schema: "transeuroogs-physical-permit-v1", LinkID: "eagle-offline-windhof-helmos", Synthetic: true,
		InputSHA256: strings.Repeat("a", 64), Stations: []string{"Windhof", "Helmos"},
		KeyBits: 256, Count: 64, LeftBudgetBits: 16384, RightBudgetBits: 16384, ReadyAtSimS: 1200}
}

func TestPhysicalPermitValidation(t *testing.T) {
	p := validPermit()
	path := filepath.Join(t.TempDir(), "permit.json")
	write := func(value PhysicalPermit) {
		raw, _ := json.Marshal(value)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(p)
	if _, delay, err := ReadPhysicalPermit(path, 600); err != nil || delay != 2*time.Second {
		t.Fatal("invalid delay", delay, err)
	}
	for _, change := range []func(*PhysicalPermit){
		func(p *PhysicalPermit) { p.Synthetic = false },
		func(p *PhysicalPermit) { p.SecurityProofValidated = true },
		func(p *PhysicalPermit) { p.Stations = []string{"Helmos", "Windhof"} },
		func(p *PhysicalPermit) { p.Count++ },
		func(p *PhysicalPermit) { p.ReadyAtSimS = -1 },
		func(p *PhysicalPermit) { p.InputSHA256 = strings.Repeat("../", 21) + "a" },
		func(p *PhysicalPermit) { p.Releases = []PhysicalRelease{{AtSimS: 1200, Count: 32}} },
		func(p *PhysicalPermit) {
			p.Releases = []PhysicalRelease{{AtSimS: 1200, Count: 32}, {AtSimS: 1200, Count: 32}}
		},
	} {
		bad := validPermit()
		change(&bad)
		write(bad)
		if _, _, err := ReadPhysicalPermit(path, 600); err == nil {
			t.Fatal("accepted invalid capacity permit")
		}
	}
	write(p)
	for _, speed := range []float64{0, -1, math.Inf(1), math.NaN(), 1e7} {
		if _, _, err := ReadPhysicalPermit(path, speed); err == nil {
			t.Fatal("accepted invalid clock")
		}
	}
	p.Count = 0
	p.LeftBudgetBits = 0
	p.RightBudgetBits = 0
	write(p)
	if _, _, err := ReadPhysicalPermit(path, 1); err != nil {
		t.Fatal("cloud/no-capacity run should expose empty inventory", err)
	}
	if err := os.WriteFile(path, []byte(`{"unexpected":"field"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadPhysicalPermit(path, 1); err == nil {
		t.Fatal("unknown fields accepted")
	}
}

func TestPhysicalSupplyRefillsWithoutRecyclingDeliveredIDs(t *testing.T) {
	repo, err := storage.NewMemory(4, nil)
	if err != nil {
		t.Fatal(err)
	}
	pair := core.Association{Master: "MASTER", Slave: "SLAVE"}
	p := validPermit()
	p.Count = 4
	p.ReadyAtSimS = .05
	p.Releases = []PhysicalRelease{{AtSimS: .05, Count: 2}, {AtSimS: .15, Count: 2}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := SupplyPhysical(ctx, repo, pair, p, 1)
	if repo.Inventory(pair).Available != 0 {
		t.Fatal("keys before physical release")
	}
	await := func(count int) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if repo.Inventory(pair).Available == count {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("physical release missed")
	}
	await(2)
	reservation, err := repo.ReserveKeys(pair, 2)
	if err != nil {
		t.Fatal(err)
	}
	first, err := repo.ConsumeReservation(pair, reservation.Token)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range first {
		clear(key.Material)
	}
	peer, err := repo.ConsumePeerKeys(pair, reservation.IDs)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range peer {
		clear(key.Material)
	}
	await(2)
	if _, err := repo.ConsumePeerKeys(pair, reservation.IDs); err == nil {
		t.Fatal("refill revived previously delivered keys")
	}
	cancel()
	<-done
}

func TestPhysicalPermitConcurrentClaimAndRestart(t *testing.T) {
	directory := t.TempDir()
	p := validPermit()
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ClaimPhysicalPermit(directory, p) == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("claimed %d times", successes.Load())
	}
	if ClaimPhysicalPermit(directory, p) == nil {
		t.Fatal("restart replayed a spent permit")
	}
	if ClaimPhysicalPermit("", p) == nil {
		t.Fatal("non-durable permit accepted")
	}
}

func TestCommonClockAndExpiredRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := WaitPhysicalClock(ctx, path); err == nil {
		t.Fatal("missing barrier released clock")
	}
	start := time.Now().Add(-time.Second)
	raw, _ := json.Marshal(start.UnixMilli())
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := WaitPhysicalClock(context.Background(), path); err != nil || got.UnixMilli() != start.UnixMilli() {
		t.Fatal("common clock mismatch")
	}
	repo, _ := storage.NewMemory(2, nil)
	pair := core.Association{Master: "A", Slave: "B"}
	p := validPermit()
	p.Count = 2
	p.ReadyAtSimS = .1
	p.Releases = []PhysicalRelease{{AtSimS: .1, Count: 2, ExpiresAtSimS: .2}}
	ctx, cancel = context.WithCancel(context.Background())
	done := SupplyPhysicalAt(ctx, repo, pair, p, 1, start)
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
	if repo.Inventory(pair).Available != 0 {
		t.Fatal("late source revived expired physical capacity")
	}
}
