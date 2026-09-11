package eaglelab

import (
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/storage"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/synthetic"
	"testing"
	"time"
)

func TestOfflineCompletionAndReplenishment(t *testing.T) {
	now := time.Now()
	pair := core.Association{Master: "GW-LU", Slave: "GW-GR"}
	memory, e := storage.NewMemory(4, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	if e = synthetic.Seed(memory, pair, 2, now, time.Minute); e != nil {
		t.Fatal(e)
	}
	d := &Delayed{Repository: memory, ReadyAt: now.Add(time.Second), Now: func() time.Time { return now }}
	if d.Inventory(pair).Available != 0 {
		t.Fatal("inventory before final relay completion")
	}
	if _, e = d.ReserveKeys(pair, 1); e == nil {
		t.Fatal("early allocation")
	}
	now = now.Add(time.Second)
	for pass := 0; pass < 2; pass++ {
		if d.Inventory(pair).Available != 2 {
			t.Fatal("completed service inventory unavailable")
		}
		res, e := d.ReserveKeys(pair, 2)
		if e != nil {
			t.Fatal(e)
		}
		master, e := d.ConsumeReservation(pair, res.Token)
		if e != nil {
			t.Fatal(e)
		}
		slave, e := d.ConsumePeerKeys(pair, res.IDs)
		if e != nil || len(slave) != len(master) {
			t.Fatal("paired retrieval failed")
		}
		for i := range master {
			if master[i].ID != slave[i].ID || string(master[i].Material) != string(slave[i].Material) {
				t.Fatal("mismatched paired key")
			}
			clear(master[i].Material)
			clear(slave[i].Material)
		}
		if d.Inventory(pair).Available != 0 {
			t.Fatal("pool failed to deplete")
		}
		if pass == 0 {
			if e = synthetic.Seed(memory, pair, 2, now, time.Minute); e != nil {
				t.Fatal(e)
			}
		}
	}
}
