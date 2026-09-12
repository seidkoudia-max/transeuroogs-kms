package postgres

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metadata"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/storage"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
)

func TestPostgresMetadataAtomicRecoveryAndPublicIsolation(t *testing.T) {
	c := configForTest(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sign, e := metadata.NewSigning(key, "test")
	if e != nil {
		t.Fatal(e)
	}
	mc := metadata.Config{Domain: "test", Issuer: "urn:test:kms", Namespace: "test", CredentialID: "test", SigningKeyFile: "fixture", MaxEvents: 100}
	a := core.Association{Master: "A", Slave: "B"}
	policy := testallocation.Setup(a)
	open := func(init bool) (*Store, *metadata.Store, *storage.Persistent) {
		t.Helper()
		pg, b, e := Open(c, init)
		if e != nil {
			t.Fatal(e)
		}
		h, b, e := metadata.Open(mc, sign, pg, b, storage.ProjectMetadata, nil)
		if e != nil {
			t.Fatal(e)
		}
		r, e := storage.OpenPersistent(100, "test", h, b, policy)
		if e != nil {
			t.Fatal(e)
		}
		return pg, h, r
	}
	pg, h, r := open(true)
	id := core.NewID()
	if e = r.StoreKey(core.Key{ID: id, Association: a, Source: "synthetic-qkd", Material: bytes.Repeat([]byte{17}, 32), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); e != nil {
		t.Fatal(e)
	}
	res, e := r.ReserveKeys(a, 1)
	if e != nil {
		t.Fatal(e)
	}
	keys, e := r.ConsumeReservation(a, res.Token)
	if e != nil {
		t.Fatal(e)
	}
	for _, k := range keys {
		clear(k.Material)
	}
	rule := testallocation.Rule()
	rule.Paused = true
	command := testallocation.Command(a, 0, rule)
	if _, e = r.ApplyCommand(testallocation.Actor, command); e != nil {
		t.Fatal(e)
	}
	p, e := h.Page("urn:test:auditor", []core.Association{a}, 0, 0, 64)
	if e != nil || len(p.Page.Events) != 4 || p.Page.Events[3].Event.Control == nil {
		t.Fatal("missing postgres-backed events", e)
	}
	var public []byte
	if e = pg.conn.QueryRow(context.Background(), "SELECT metadata FROM kms_meta.state WHERE namespace=$1", c.Namespace).Scan(&public); e != nil {
		t.Fatal(e)
	}
	for _, private := range []string{"Provenance", "jws", "private_attempt_aliases", "Allocation", testallocation.Actor, string(res.Token)} {
		if strings.Contains(string(public), private) {
			t.Fatal("rich investigator data leaked to coarse database observer")
		}
	}
	r.Close()
	_, h, r = open(false)
	defer r.Close()
	after, e := h.Page("urn:test:auditor", []core.Association{a}, 0, 0, 64)
	if e != nil || len(after.Page.Events) != 4 || after.Page.Events[3].Event.ID != p.Page.Events[3].Event.ID {
		t.Fatal("history not recovered atomically", e)
	}
	if _, e = r.ConsumeReservation(a, res.Token); e == nil {
		t.Fatal("revived consumed reservation")
	}
	if _, e = r.ConsumePeerKeys(a, []core.KeyID{id}); e == nil {
		t.Fatal("PostgreSQL restart lost delivery policy")
	}
	if result, e := r.ApplyCommand(testallocation.Actor, command); e != nil || result.Revision != 1 {
		t.Fatal("PostgreSQL command replay failed", e)
	}
}
