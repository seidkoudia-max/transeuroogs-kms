package ingest

import (
	"bytes"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"testing"
	"time"
)

func TestUnknownGenerationRejectedBeforeProviderAndPauseAfterReservation(t *testing.T) {
	setup := testallocation.Setup(pair)
	setup.Config.Apps[0].Rule.MaxGenerationAgeSeconds = 30
	d := &testallocation.Disk{}
	provider := &fakeProvider{}
	c := profile(t, "master")
	r, err := OpenStore(c, pair, 100, provider, d, nil, setup)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.ReserveKeys(pair, 1); err == nil || provider.calls.Load() != 0 {
		t.Fatal("unknown metadata consumed provider keys")
	}
	rule := testallocation.Rule()
	if _, err = r.ApplyCommand(testallocation.Actor, testallocation.Command(pair, 0, rule)); err != nil {
		t.Fatal(err)
	}
	res, err := r.ReserveKeys(pair, 2)
	if err != nil {
		t.Fatal(err)
	}
	rule.Paused = true
	if _, err = r.ApplyCommand(testallocation.Actor, testallocation.Command(pair, 1, rule)); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ConsumeReservation(pair, res.Token); err == nil {
		t.Fatal("reservation bypassed pause")
	}
	r.Close()
	r, err = OpenStore(c, pair, 100, provider, d, bytes.Clone(d.Raw), setup)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err = r.ConsumeReservation(pair, res.Token); err == nil {
		t.Fatal("restart lost pause")
	}
}
func TestProviderResponseThatAgesPastLocalTTLBurnsKnownIDs(t *testing.T) {
	for _, role := range []string{"master", "slave"} {
		t.Run(role, func(t *testing.T) {
			setup := testallocation.Setup(pair)
			setup.Config.Apps[0].Rule.MaxLocalAgeSeconds = 1
			d := &testallocation.Disk{}
			provider := &fakeProvider{}
			c := profile(t, role)
			r, err := OpenStore(c, pair, 100, provider, d, nil, setup)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			now := time.Now()
			r.now = func() time.Time { return now }
			id := core.NewID()
			delayed := func() ([]core.Delivery, error) {
				now = now.Add(2 * time.Second)
				return []core.Delivery{{ID: id, Material: bytes.Repeat([]byte{1}, 32)}}, nil
			}
			provider.allocate = func(int) ([]core.Delivery, error) { return delayed() }
			provider.retrieve = func([]core.KeyID) ([]core.Delivery, error) { return delayed() }
			if role == "master" {
				_, err = r.ReserveKeys(pair, 1)
			} else {
				_, err = r.ConsumePeerKeys(pair, []core.KeyID{id})
			}
			if err == nil || r.s.Keys[id] == nil || r.s.Keys[id].State != core.Invalid || len(r.s.Keys[id].Material) != 0 {
				t.Fatal("late response was not tombstoned")
			}
			if role == "slave" {
				if _, e := r.ConsumePeerKeys(pair, []core.KeyID{id}); e == nil || provider.calls.Load() != 1 {
					t.Fatal("retry consumed another provider key")
				}
			}
		})
	}
}
