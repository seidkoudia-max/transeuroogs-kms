package metadata_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metadata"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/storage"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testfederation"
	"testing"
	"time"
)

func TestSignedPoolIncidentHistorySurvivesRestartWithoutDuplicateActions(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sign, _ := metadata.NewSigning(k, "test")
	c := metadata.Config{Domain: "test", Issuer: "urn:test:kms", Namespace: "test", CredentialID: "test", SigningKeyFile: "fixture", MaxEvents: 100}
	a := core.Association{Master: "A", Slave: "B"}
	f := testfederation.Config(a)
	d := &disk{}
	h, raw, e := metadata.Open(c, sign, d, nil, storage.ProjectMetadata, nil)
	if e != nil {
		t.Fatal(e)
	}
	r, e := storage.OpenPersistentControlled(10, "test", h, raw, f)
	if e != nil {
		t.Fatal(e)
	}
	id := core.NewID()
	now := time.Now()
	if e = r.StoreKey(core.Key{ID: id, Association: a, Material: bytes.Repeat([]byte{1}, 32), Source: "synthetic-qkd", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); e != nil {
		t.Fatal(e)
	}
	res, e := r.ReserveKeys(a, 1)
	if e != nil {
		t.Fatal(e)
	}
	cmd := testfederation.Command(f, 0, core.NewID(), "invalidate")
	if _, e = r.ApplyProtection(testfederation.Actor, cmd); e != nil {
		t.Fatal(e)
	}
	r.Close()
	h, raw, e = metadata.Open(c, sign, d, bytes.Clone(d.raw), storage.ProjectMetadata, nil)
	if e != nil {
		t.Fatal("signed recovery", e)
	}
	r, e = storage.OpenPersistentControlled(10, "test", h, raw, f)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if _, e = r.ConsumeReservation(a, res.Token); e == nil {
		t.Fatal("history-enabled restart revived key")
	}
	page, e := h.Page("urn:test:reader", []core.Association{a}, 0, 0, 64)
	if e != nil {
		t.Fatal(e)
	}
	mappings, actions := 0, 0
	for _, ev := range page.Page.Events {
		if ev.Event.Protection != nil {
			if ev.Event.Protection.Mapping != nil {
				mappings++
			}
			if ev.Event.Protection.Action != nil {
				actions++
			}
		}
	}
	if mappings != 1 || actions != 1 {
		t.Fatal("missing or duplicate protection history")
	}
	if _, e = r.ApplyProtection(testfederation.Actor, cmd); e != nil {
		t.Fatal(e)
	}
}
