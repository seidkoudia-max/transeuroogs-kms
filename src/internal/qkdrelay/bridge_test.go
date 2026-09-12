package qkdrelay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/etsi020"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/peering"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/storage"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/upstream"
	"testing"
	"time"
)

type linkProvider struct {
	repo            core.Repository
	pair            core.Association
	alloc, retrieve int
	fail            bool
}

func (p *linkProvider) Allocate(n int) ([]core.Delivery, error) {
	p.alloc++
	r, e := p.repo.ReserveKeys(p.pair, n)
	if e != nil {
		return nil, e
	}
	d, e := p.repo.ConsumeReservation(p.pair, r.Token)
	if p.fail {
		wipe(d)
		return nil, core.ErrUnavailable
	}
	return d, e
}
func (p *linkProvider) Retrieve(ids []core.KeyID) ([]core.Delivery, error) {
	p.retrieve++
	d, e := p.repo.ConsumePeerKeys(p.pair, ids)
	if p.fail {
		wipe(d)
		return nil, core.ErrUnavailable
	}
	return d, e
}
func linkConfig(role string) *upstream.Config {
	return &upstream.Config{Profile: upstream.Profile, URL: "https://provider", ServerIdentity: "urn:test:provider", GatewayIdentity: "urn:test:gateway", GatewayMaster: "GW-A", GatewaySlave: "GW-B", Role: role, RemoteKMEID: "remote", PKIDir: "unused", CertificateName: "gateway", StateDir: "unused", LifetimeSeconds: 60}
}
func configs() (peering.Config, peering.Config) {
	a := peering.Config{Identity: "urn:test:a", PublicURL: "https://a", StateDir: "a-state", QKDStateDir: "a-qkd", Peers: map[string]peering.Peer{"b": {URL: "https://b", Identity: "urn:test:b", Mode: peering.QKDRelay, Link: linkConfig("master")}}}
	b := peering.Config{Identity: "urn:test:b", PublicURL: "https://b", StateDir: "b-state", QKDStateDir: "b-qkd", Peers: map[string]peering.Peer{"a": {URL: "https://a", Identity: "urn:test:a", Mode: peering.QKDRelay, Incoming: true, Link: linkConfig("slave")}}}
	return a, b
}
func transfer() etsi020.Transfer {
	expires, _ := json.Marshal(time.Now().UTC().Add(time.Minute))
	return etsi020.Transfer{Keys: []etsi020.Key{{ID: core.NewID(), Value: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), Extension: etsi020.Extension{LifetimeExtension: expires}}}, Initiator: "A", Targets: []string{"B"}, Callback: "https://a/qkd/v1/ext_keys/ack"}
}
func provider(t *testing.T) *linkProvider {
	t.Helper()
	pair := core.Association{Master: "GW-A", Slave: "GW-B"}
	r, _ := storage.NewMemory(10, nil)
	for n := range 4 {
		if e := r.StoreKey(core.Key{ID: core.NewID(), Association: pair, Material: bytes.Repeat([]byte{byte(n + 1)}, 32), Source: "synthetic-qkd", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); e != nil {
			t.Fatal(e)
		}
	}
	return &linkProvider{repo: r, pair: pair}
}
func TestOneLinkKeyPerTransferAndLostHandoffRestart(t *testing.T) {
	a, b := configs()
	p := provider(t)
	leftDisk, rightDisk := &testallocation.Disk{}, &testallocation.Disk{}
	left, e := Open(a, map[string]Provider{"b": p}, 10, leftDisk, nil)
	if e != nil {
		t.Fatal(e)
	}
	right, e := Open(b, map[string]Provider{"a": p}, 10, rightDisk, nil)
	if e != nil {
		t.Fatal(e)
	}
	x := transfer()
	frame, e := left.Seal("b", x)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains([]byte(frame.JWE), []byte(x.Keys[0].Value)) {
		t.Fatal("plaintext transfer in frame")
	}
	for range 2 {
		again, e := left.Seal("b", x)
		if e != nil || again != frame {
			t.Fatal("retry changed ciphertext", e)
		}
	}
	if p.alloc != 1 {
		t.Fatal("retry consumed another link key")
	}
	handoffs := 0
	callback := func(peer string, v etsi020.Transfer) error {
		handoffs++
		if peer != "a" || v.Keys[0].Value != x.Keys[0].Value {
			t.Fatal("wrong decrypted transfer")
		}
		return core.ErrUnavailable
	}
	if e = right.Accept("a", frame, callback); e == nil {
		t.Fatal("uncommitted handoff acknowledged")
	}
	right.Close()
	right, e = Open(b, map[string]Provider{"a": p}, 10, rightDisk, bytes.Clone(rightDisk.Raw))
	if e != nil {
		t.Fatal(e)
	}
	defer right.Close()
	callback = func(string, etsi020.Transfer) error { handoffs++; return nil }
	for range 2 {
		if e = right.Accept("a", frame, callback); e != nil {
			t.Fatal(e)
		}
	}
	if p.retrieve != 1 || handoffs != 2 || len(right.s.Inbound) != 1 {
		t.Fatal("handoff replay fetched or delivered again")
	}
	left.Close()
	left, e = Open(a, map[string]Provider{"b": p}, 10, leftDisk, bytes.Clone(leftDisk.Raw))
	if e != nil {
		t.Fatal(e)
	}
	defer left.Close()
	if again, e := left.Seal("b", x); e != nil || again != frame || p.alloc != 1 {
		t.Fatal("outbound recovery reused link key", e)
	}
	x.Keys[0].Value = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	if _, e = left.Seal("b", x); e == nil {
		t.Fatal("same application KID carried different material")
	}
}
func TestUncertainConsumingCallNeverRetriesAndTamperIsBurned(t *testing.T) {
	a, b := configs()
	p := provider(t)
	p.fail = true
	d := &testallocation.Disk{}
	left, e := Open(a, map[string]Provider{"b": p}, 10, d, nil)
	if e != nil {
		t.Fatal(e)
	}
	x := transfer()
	if _, e = left.Seal("b", x); e == nil {
		t.Fatal("lost allocation reply accepted")
	}
	left.Close()
	p.fail = false
	left, e = Open(a, map[string]Provider{"b": p}, 10, d, bytes.Clone(d.Raw))
	if e != nil {
		t.Fatal(e)
	}
	defer left.Close()
	if _, e = left.Seal("b", x); e == nil || p.alloc != 1 {
		t.Fatal("uncertain allocate retried")
	}
	frame, e := left.Seal("b", transfer())
	if e != nil {
		t.Fatal(e)
	}
	right, e := Open(b, map[string]Provider{"a": p}, 10, &testallocation.Disk{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer right.Close()
	bad := frame
	pos := len(bad.JWE) - 8
	replacement := "A"
	if bad.JWE[pos] == 'A' {
		replacement = "B"
	}
	bad.JWE = bad.JWE[:pos] + replacement + bad.JWE[pos+1:]
	called := false
	callback := func(string, etsi020.Transfer) error { called = true; return nil }
	if e = right.Accept("a", bad, callback); e == nil || called {
		t.Fatal("tampered ciphertext delivered")
	}
	if e = right.Accept("a", frame, callback); e == nil || p.retrieve != 1 || called {
		t.Fatal("burned link key fetched again")
	}
}

type partialProvider struct {
	id   core.KeyID
	fail bool
}

func (p *partialProvider) Allocate(int) ([]core.Delivery, error) {
	d := []core.Delivery{{ID: p.id, Material: bytes.Repeat([]byte{7}, 32)}}
	if p.fail {
		return d, core.ErrUnavailable
	}
	return d, nil
}
func (*partialProvider) Retrieve([]core.KeyID) ([]core.Delivery, error) {
	return nil, core.ErrUnavailable
}

func TestKnownLinkIDInFailedReplyCannotBeRecycledAfterRestart(t *testing.T) {
	a, _ := configs()
	p := &partialProvider{id: core.NewID(), fail: true}
	d := &testallocation.Disk{}
	b, e := Open(a, map[string]Provider{"b": p}, 10, d, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.Seal("b", transfer()); e == nil {
		t.Fatal("partial failed reply accepted")
	}
	b.Close()
	b, e = Open(a, map[string]Provider{"b": p}, 10, d, bytes.Clone(d.Raw))
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	p.fail = false
	if _, e = b.Seal("b", transfer()); e == nil {
		t.Fatal("known uncertain link ID reused for a different application key")
	}
}
