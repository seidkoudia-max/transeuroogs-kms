package qkdrelay_test

import (
	"bytes"
	"context"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/etsi020"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/peering"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/qkdrelay"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/relay"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/storage"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/upstream"
	"testing"
	"time"
)

type provider struct {
	repo                 core.Repository
	pair                 core.Association
	allocated, retrieved int
}

func (p *provider) Allocate(n int) ([]core.Delivery, error) {
	p.allocated++
	r, e := p.repo.ReserveKeys(p.pair, n)
	if e != nil {
		return nil, e
	}
	return p.repo.ConsumeReservation(p.pair, r.Token)
}
func (p *provider) Retrieve(ids []core.KeyID) ([]core.Delivery, error) {
	p.retrieved++
	return p.repo.ConsumePeerKeys(p.pair, ids)
}

type node struct {
	disk   *testallocation.Disk
	config peering.Config
	engine *relay.Engine
	bridge *qkdrelay.Bridge
}
type transport struct {
	name  string
	nodes map[string]*node
}

func (t transport) Probe(context.Context, string) error { return nil }
func (t transport) Send(_ context.Context, peer string, v etsi020.Transfer) error {
	frame, e := t.nodes[t.name].bridge.Seal(peer, v)
	if e != nil {
		return e
	}
	return t.nodes[peer].bridge.Accept(t.name, frame, t.nodes[peer].engine.Accept)
}
func (t transport) Ack(_ context.Context, peer string, a []etsi020.Ack) error {
	return t.nodes[peer].engine.Acknowledge(t.name, a)
}
func (t transport) Void(_ context.Context, peer string, v etsi020.Void) error {
	return t.nodes[peer].engine.Void(t.name, v)
}
func link(role string) *upstream.Config {
	return &upstream.Config{Profile: upstream.Profile, URL: "https://provider", ServerIdentity: "urn:test:provider", GatewayIdentity: "urn:test:gateway", GatewayMaster: "GW-A", GatewaySlave: "GW-B", Role: role, RemoteKMEID: "remote", PKIDir: "unused", CertificateName: "gateway", StateDir: "unused", LifetimeSeconds: 60}
}

func TestWindhofJFKBetzdorfConsumesBothLinkPools(t *testing.T) {
	app := core.Association{Master: "APP-WINDHOF", Slave: "APP-BETZDORF"}
	names := []string{"windhof", "jfk", "betzdorf"}
	nodes := map[string]*node{}
	links := []*provider{}
	for i := range 2 {
		a := core.Association{Master: "LINK-A", Slave: "LINK-B"}
		repo, _ := storage.NewMemory(4, nil)
		if e := repo.StoreKey(core.Key{ID: core.NewID(), Association: a, Material: bytes.Repeat([]byte{byte(20 + i)}, 32), Source: "synthetic-qkd", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); e != nil {
			t.Fatal(e)
		}
		links = append(links, &provider{repo: repo, pair: a})
	}
	for i, name := range names {
		cfg := peering.Config{Identity: "urn:test:" + name, PublicURL: "https://" + name, StateDir: name + "-engine", QKDStateDir: name + "-qkd", Peers: map[string]peering.Peer{}, Routes: map[string][]string{}, TargetKMEs: map[string]string{app.Slave: "betzdorf"}}
		providers := map[string]qkdrelay.Provider{}
		if i == 0 {
			cfg.LocalSAEs = []string{app.Master}
		}
		if i == 2 {
			cfg.LocalSAEs = []string{app.Slave}
		}
		if i > 0 {
			previous := names[i-1]
			cfg.Peers[previous] = peering.Peer{URL: "https://" + previous, Identity: "urn:test:" + previous, Mode: peering.QKDRelay, Incoming: true, Link: link("slave")}
			providers[previous] = links[i-1]
		}
		if i < 2 {
			next := names[i+1]
			cfg.Peers[next] = peering.Peer{URL: "https://" + next, Identity: "urn:test:" + next, Mode: peering.QKDRelay, Link: link("master")}
			providers[next] = links[i]
			cfg.Routes[app.Slave] = []string{next}
		}
		bridge, e := qkdrelay.Open(cfg, providers, 10, &testallocation.Disk{}, nil)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(bridge.Close)
		disk := &testallocation.Disk{}
		engine, e := relay.OpenStore(cfg, []core.Association{app}, 10, transport{name, nodes}, disk, nil)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(engine.Close)
		nodes[name] = &node{disk: disk, config: cfg, engine: engine, bridge: bridge}
	}
	id := core.NewID()
	material := bytes.Repeat([]byte{5}, 32)
	expiry := time.Now().UTC().Add(time.Minute)
	if e := nodes["windhof"].engine.StoreKey(core.Key{ID: id, Association: app, Material: material, Source: "synthetic-qkd", CreatedAt: time.Now(), ExpiresAt: expiry}); e != nil {
		t.Fatal(e)
	}
	for range 8 {
		for _, name := range names {
			nodes[name].engine.Step(context.Background())
		}
	}
	res, e := nodes["windhof"].engine.ReserveKeys(app, 1)
	if e != nil {
		t.Fatal("protected path not ready", e)
	}
	left, e := nodes["windhof"].engine.ConsumeReservation(app, res.Token)
	if e != nil {
		t.Fatal(e)
	}
	right, e := nodes["betzdorf"].engine.ConsumePeerKeys(app, []core.KeyID{id})
	if e != nil || !bytes.Equal(left[0].Material, right[0].Material) {
		t.Fatal("remote copies differ", e)
	}
	for _, d := range append(left, right...) {
		clear(d.Material)
	}
	for _, p := range links {
		if p.allocated != 1 || p.retrieved != 1 || p.repo.Inventory(p.pair).Available != 0 {
			t.Fatal("relay bypassed separate link-key consumption")
		}
	}
	remote, e := nodes["betzdorf"].engine.Metadata(id)
	if e != nil || !remote.ExpiresAt.Equal(expiry) {
		t.Fatal("relay extended key lifetime", e)
	}
	projection, e := relay.ProjectMetadata(nodes["jfk"].config)(nodes["jfk"].disk.Raw)
	if e != nil || projection.Keys[id].HoldingMaterial {
		t.Fatal("trusted relay retained application key after handoff")
	}
}
