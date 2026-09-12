package metadata_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metadata"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/storage"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
)

func TestSignedAllocationHistorySharesKeyCommitAndVerifiesOffline(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sign, _ := metadata.NewSigning(key, "test")
	c := metadata.Config{Domain: "test", Issuer: "urn:test:kms", Namespace: "test", CredentialID: "test", SigningKeyFile: "fixture", MaxEvents: 100}
	d := &disk{}
	a := core.Association{Master: "A", Slave: "B"}
	setup := testallocation.Setup(a)
	h, b, err := metadata.Open(c, sign, d, nil, storage.ProjectMetadata, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := storage.OpenPersistent(10, "test", h, b, setup)
	if err != nil {
		t.Fatal(err)
	}
	rule := testallocation.Rule()
	rule.Paused = true
	cmd := testallocation.Command(a, 0, rule)
	if _, err = r.ApplyCommand(testallocation.Actor, cmd); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ApplyCommand(testallocation.Actor, cmd); err != nil {
		t.Fatal(err)
	}
	r.Close()
	h, b, err = metadata.Open(c, sign, d, bytes.Clone(d.raw), storage.ProjectMetadata, nil)
	if err != nil {
		t.Fatal("history recovery", err)
	}
	r, err = storage.OpenPersistent(10, "test", h, b, setup)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	page, err := h.Page("urn:test:investigator", []core.Association{a}, 0, 0, metadata.MaxPage)
	if err != nil || len(page.Page.Events) != 1 || page.Page.Events[0].Event.Control == nil {
		t.Fatal("missing or duplicated command event", err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	path := filepath.Join(t.TempDir(), "public.pem")
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0600); err != nil {
		t.Fatal(err)
	}
	trust := []metadata.Trust{{Issuer: c.Issuer, Domain: c.Domain, Namespace: c.Namespace, CredentialID: c.CredentialID, PublicKeyFile: path, Pairs: []core.Association{a}, ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour)}}
	if _, _, err = metadata.VerifyPages([]metadata.SignedPage{page}, trust, "urn:test:investigator"); err != nil {
		t.Fatal("offline control verification", err)
	}
	page.Page.Events[0].Event.Control.Actor = "urn:test:forged"
	if _, _, err = metadata.VerifyPages([]metadata.SignedPage{page}, trust, "urn:test:investigator"); err == nil {
		t.Fatal("tampered actor accepted")
	}
}

type disk struct {
	raw  []byte
	fail bool
}

func (d *disk) Save(b []byte) error {
	d.raw = bytes.Clone(b)
	if d.fail {
		return errors.New("lost commit result")
	}
	return nil
}
func (*disk) Close() {}

func TestPersistentDeliveryRaceAndAmbiguousCommitWithMetadata(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sign, _ := metadata.NewSigning(k, "test")
	c := metadata.Config{Domain: "test", Issuer: "urn:test:local", Namespace: "test", CredentialID: "test", SigningKeyFile: "fixture", MaxEvents: 100}
	d := &disk{}
	h, b, e := metadata.Open(c, sign, d, nil, storage.ProjectMetadata, nil)
	if e != nil {
		t.Fatal(e)
	}
	r, e := storage.OpenPersistent(100, "test", h, b)
	if e != nil {
		t.Fatal(e)
	}
	a := core.Association{Master: "A", Slave: "B"}
	id := core.NewID()
	if e = r.StoreKey(core.Key{ID: id, Association: a, Material: bytes.Repeat([]byte{5}, 32), Source: "synthetic-qkd", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); e != nil {
		t.Fatal(e)
	}
	reservation, e := r.ReserveKeys(a, 1)
	if e != nil {
		t.Fatal(e)
	}
	var success atomic.Int32
	var group sync.WaitGroup
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			if keys, e := r.ConsumeReservation(a, reservation.Token); e == nil {
				success.Add(1)
				for _, k := range keys {
					clear(k.Material)
				}
			}
		}()
	}
	group.Wait()
	if success.Load() != 1 {
		t.Fatal("concurrent delivery was not single-use")
	}
	d.fail = true
	keys, e := r.ConsumePeerKeys(a, []core.KeyID{id})
	if e == nil || len(keys) != 0 {
		t.Fatal("released bytes after ambiguous event commit")
	}
	r.Close()
	d.fail = false
	h, b, e = metadata.Open(c, sign, d, bytes.Clone(d.raw), storage.ProjectMetadata, nil)
	if e != nil {
		t.Fatal("metadata restart", e)
	}
	r, e = storage.OpenPersistent(100, "test", h, b)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if _, e = r.ConsumePeerKeys(a, []core.KeyID{id}); e == nil {
		t.Fatal("reissued peer delivery after restart")
	}
	p, e := h.Page("urn:test:auditor", []core.Association{a}, 0, 0, 64)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, e := range p.Page.Events {
		for _, action := range e.Event.Actions {
			if action == "master_CONSUMED" || action == "slave_CONSUMED" {
				count++
			}
		}
	}
	if count != 2 {
		t.Fatal("delivery not matched by exactly one event")
	}
	if _, e = storage.OpenPersistent(100, "test", d, bytes.Clone(d.raw)); e == nil {
		t.Fatal("metadata disabled on managed snapshot")
	}
}
