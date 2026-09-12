package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/etsi020"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metadata"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
)

func TestUnknownVoidHasTerminalMetadataWithoutInventedLifetime(t *testing.T) {
	n := setup(t, false)
	old := n.nodes["gr"]
	cfg := old.cfg
	old.Close()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sign, _ := metadata.NewSigning(key, "test")
	mc := metadata.Config{Domain: "test", Issuer: cfg.Identity, Namespace: "test", CredentialID: "test", SigningKeyFile: "unused", MaxEvents: 100}
	h, b, err := metadata.Open(mc, sign, &testallocation.Disk{}, nil, ProjectMetadata(cfg), nil)
	if err != nil {
		t.Fatal(err)
	}
	e, err := OpenStore(cfg, []core.Association{association}, 100, link{n, "gr"}, h, b)
	if err != nil {
		t.Fatal(err)
	}
	n.nodes["gr"] = e
	id := core.NewID()
	if err = e.Void("lu", etsi020.Void{IDs: []core.KeyID{id}, Initiator: association.Master, Targets: []string{association.Slave}, Callback: cfg.Peers["lu"].URL + "/kmapi/v1/ext_keys/ack"}); err != nil {
		t.Fatal("unknown void failed", err)
	}
	page, err := h.Page("urn:test:investigator", []core.Association{association}, 0, 0, 64)
	if err != nil || len(page.Page.Events) != 1 {
		t.Fatal(err)
	}
	r := page.Page.Events[0].Event.Record
	if r == nil || !r.Voiding || !r.Uncertain || r.HoldingMaterial || !r.LocalExpiresAt.Equal(r.CollectionIntent) {
		t.Fatal("invented unknown key custody")
	}
}

func TestSignedMultipathIncidentTraceAndMetadataRestart(t *testing.T) {
	n := setup(t, true)
	histories := map[string]*metadata.Store{}
	signers := map[string]*metadata.Signing{}
	configs := map[string]metadata.Config{}
	trust := []metadata.Trust{}
	for name, old := range n.nodes {
		cfg := old.cfg
		old.Close()
		cfg.StateDir = filepath.Join(t.TempDir(), "state")
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sign, e := metadata.NewSigning(key, "test-"+name)
		if e != nil {
			t.Fatal(e)
		}
		z := int64(0)
		mc := metadata.Config{Domain: "test", Issuer: cfg.Identity, Namespace: "network-test", CredentialID: "test-" + name, SigningKeyFile: "fixture", MaxEvents: 1000, ClockUncertaintyMS: &z}
		inner, raw, e := durable.Open(cfg.StateDir, "transeuroogs-relay-state-v1")
		if e != nil {
			t.Fatal(e)
		}
		h, raw, e := metadata.Open(mc, sign, inner, raw, ProjectMetadata(cfg), nil)
		if e != nil {
			t.Fatal(e)
		}
		node, e := OpenStore(cfg, []core.Association{association}, 1000, link{n, name}, h, raw)
		if e != nil {
			t.Fatal(e)
		}
		node.retry = 0
		n.nodes[name] = node
		histories[name], signers[name], configs[name] = h, sign, mc
		pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		path := filepath.Join(t.TempDir(), "public.pem")
		if os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0600) != nil {
			t.Fatal("write public credential")
		}
		trust = append(trust, metadata.Trust{Issuer: mc.Issuer, Domain: mc.Domain, Namespace: mc.Namespace, CredentialID: mc.CredentialID, PublicKeyFile: path, Pairs: []core.Association{association}, ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour)})
	}
	seed(t, n.nodes["lu"], 4)
	n.pump(20)
	keys := consume(t, n, 4)
	for _, k := range keys {
		clear(k.Material)
	}
	pages := []metadata.SignedPage{}
	for _, h := range histories {
		p, e := h.Page("urn:test:auditor", []core.Association{association}, 0, 0, 64)
		if e != nil || !p.Page.Complete {
			t.Fatal("history export", e)
		}
		pages = append(pages, p)
	}
	events, coverage, e := metadata.VerifyPages(pages, trust, "urn:test:auditor")
	if e != nil {
		t.Fatal("verify federation exports", e)
	}
	var first, last *metadata.Event
	for i := range events {
		ev := &events[i]
		if ev.Issuer != "urn:kme:relay-a" || ev.Record == nil {
			continue
		}
		if first == nil && slices.Contains(ev.Actions, "custody_started") {
			first = ev
		}
		if first != nil && ev.Record.Key == first.Record.Key && slices.Contains(ev.Actions, "material_cleared") {
			last = ev
			break
		}
	}
	if first == nil || last == nil {
		t.Fatal("relay custody not recorded")
	}
	z := int64(0)
	q := metadata.Query{IncidentID: core.NewID(), Subject: "urn:kme:relay-a", Kind: "material_exposure", Start: first.RecordedAt, End: last.RecordedAt, ClockUncertaintyMS: &z}
	report, e := metadata.Trace(q, events, coverage)
	if e != nil || len(report.Findings) == 0 {
		t.Fatal("incident missed relay", e)
	}
	for _, f := range report.Findings {
		if n.nodes["relay-a"].s.Keys[f.Key.ID] == nil || n.nodes["relay-b"].s.Keys[f.Key.ID] != nil || len(f.Deliveries) != 2 {
			t.Fatal("incorrect path or endpoint impact")
		}
	}
	old := n.nodes["relay-a"]
	cfg := old.cfg
	old.Close()
	if node, e := Open(cfg, []core.Association{association}, 1000, link{n, "relay-a"}); e == nil {
		node.Close()
		t.Fatal("managed history silently disabled")
	}
	inner, raw, e := durable.Open(cfg.StateDir, "transeuroogs-relay-state-v1")
	if e != nil {
		t.Fatal(e)
	}
	h, raw, e := metadata.Open(configs["relay-a"], signers["relay-a"], inner, raw, ProjectMetadata(cfg), nil)
	if e != nil {
		t.Fatal("metadata recovery", e)
	}
	n.nodes["relay-a"], e = OpenStore(cfg, []core.Association{association}, 1000, link{n, "relay-a"}, h, raw)
	if e != nil {
		t.Fatal(e)
	}
	p, e := h.Page("urn:test:auditor", []core.Association{association}, 0, 0, 64)
	if e != nil {
		t.Fatal(e)
	}
	seen := false
	for _, ev := range p.Page.Events {
		if ev.Event.ID == first.ID {
			seen = true
		}
	}
	if !seen {
		t.Fatal("lost stable event binding")
	}
}
