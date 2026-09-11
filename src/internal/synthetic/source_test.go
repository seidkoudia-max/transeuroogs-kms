package synthetic

import (
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/storage"
)

func TestSyntheticSource(t *testing.T) {
	repo, err := storage.NewMemory(10, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := core.Association{Master: "A", Slave: "B"}
	if err := Seed(repo, a, 0, time.Now(), time.Hour); err != nil || repo.Inventory(a).Available != 0 {
		t.Fatal("empty source provisioned keys")
	}
	for _, count := range []int{-1, 100001} {
		if err := Seed(repo, a, count, time.Now(), time.Hour); err == nil {
			t.Fatal("invalid count accepted")
		}
	}
	if err := Seed(repo, a, 1, time.Now(), 0); err == nil {
		t.Fatal("invalid TTL accepted")
	}
	if err := Seed(repo, a, 10, time.Now(), time.Hour); err != nil {
		t.Fatal(err)
	}
	if repo.Inventory(a).Available != 10 {
		t.Fatal("seed count mismatch")
	}
}
