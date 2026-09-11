package ingest

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/upstream"
)

type fakeProvider struct {
	calls    atomic.Int32
	allocate func(int) ([]core.Delivery, error)
	retrieve func([]core.KeyID) ([]core.Delivery, error)
}

func (p *fakeProvider) Allocate(n int) ([]core.Delivery, error) {
	p.calls.Add(1)
	if p.allocate != nil {
		return p.allocate(n)
	}
	var out []core.Delivery
	for range n {
		b := make([]byte, 32)
		rand.Read(b)
		out = append(out, core.Delivery{ID: core.NewID(), Material: b})
	}
	return out, nil
}
func (p *fakeProvider) Retrieve(ids []core.KeyID) ([]core.Delivery, error) {
	p.calls.Add(1)
	if p.retrieve != nil {
		return p.retrieve(ids)
	}
	var out []core.Delivery
	for _, id := range ids {
		b := make([]byte, 32)
		rand.Read(b)
		out = append(out, core.Delivery{ID: id, Material: b})
	}
	return out, nil
}
func (p *fakeProvider) Inventory() (core.Inventory, error) {
	return core.Inventory{Available: 100, Capacity: 100}, nil
}

var pair = core.Association{Master: "APP-LU", Slave: "APP-GR"}

func profile(t *testing.T, role string) upstream.Config {
	t.Helper()
	return upstream.Config{Profile: upstream.Profile, URL: "https://localhost:8443", ServerIdentity: "urn:test:provider", GatewayIdentity: "urn:test:gateway", GatewayMaster: "GW-LU", GatewaySlave: "GW-GR", Role: role, RemoteKMEID: "remote", StateDir: filepath.Join(t.TempDir(), "state"), PKIDir: "unused", CertificateName: "gateway", LifetimeSeconds: 60}
}
func open(t *testing.T, c upstream.Config, p Provider) *Repository {
	t.Helper()
	r, e := Open(c, pair, 100, p)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(r.Close)
	return r
}

func TestMasterReservationDurabilityAndRoleIsolation(t *testing.T) {
	c := profile(t, "master")
	p := &fakeProvider{}
	r := open(t, c, p)
	if _, e := r.ReserveKeys(core.Association{Master: "OTHER", Slave: pair.Slave}, 1); !errors.Is(e, core.ErrUnauthorized) {
		t.Fatal("wrong pair accepted")
	}
	if _, e := r.ConsumePeerKeys(pair, []core.KeyID{core.NewID()}); !errors.Is(e, core.ErrUnauthorized) {
		t.Fatal("wrong role accepted")
	}
	if e := r.StoreKey(core.Key{}); !errors.Is(e, core.ErrUnauthorized) {
		t.Fatal("external injection accepted")
	}
	if p.calls.Load() != 0 {
		t.Fatal("unauthorised request reached provider")
	}
	res, e := r.ReserveKeys(pair, 2)
	if e != nil {
		t.Fatal(e)
	}
	r.Close()
	r = open(t, c, p)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys, e := r.ConsumeReservation(pair, res.Token)
			if e == nil {
				successes.Add(1)
				if len(keys) != 2 {
					t.Error("incomplete batch")
				}
				wipe(keys)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || p.calls.Load() != 1 {
		t.Fatal("reservation replay or upstream reallocation")
	}
	r.Close()
	r = open(t, c, p)
	if _, e = r.ConsumeReservation(pair, res.Token); e == nil {
		t.Fatal("replay after restart")
	}
	for _, id := range res.IDs {
		m, e := r.Metadata(id)
		if e != nil || m.MasterState != core.Consumed || m.SlaveState != core.Invalid {
			t.Fatal("incorrect local delivery state")
		}
	}
}

func TestSlaveAtomicReplayAndRestart(t *testing.T) {
	c := profile(t, "slave")
	p := &fakeProvider{}
	r := open(t, c, p)
	ids := []core.KeyID{core.NewID(), core.NewID()}
	if _, e := r.ConsumePeerKeys(pair, []core.KeyID{ids[0], ids[0]}); e == nil {
		t.Fatal("duplicate batch accepted")
	}
	if p.calls.Load() != 0 {
		t.Fatal("invalid batch consumed upstream")
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys, e := r.ConsumePeerKeys(pair, ids)
			if e == nil {
				successes.Add(1)
				wipe(keys)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || p.calls.Load() != 1 {
		t.Fatal("parallel replay reached provider")
	}
	fresh := core.NewID()
	if _, e := r.ConsumePeerKeys(pair, []core.KeyID{fresh, ids[0]}); e == nil {
		t.Fatal("mixed replay batch accepted")
	}
	if _, ok := r.s.Keys[fresh]; ok {
		t.Fatal("failed batch mutated fresh ID")
	}
	r.Close()
	r = open(t, c, p)
	if _, e := r.ConsumePeerKeys(pair, ids); e == nil || p.calls.Load() != 1 {
		t.Fatal("replay after restart")
	}
}

func TestUncertainSlaveDeliveryNeverRetriesAcrossRestart(t *testing.T) {
	for _, kind := range []string{"lost response", "wrong ID", "short batch", "crash"} {
		t.Run(kind, func(t *testing.T) {
			c := profile(t, "slave")
			ids := []core.KeyID{core.NewID(), core.NewID()}
			p := &fakeProvider{retrieve: func([]core.KeyID) ([]core.Delivery, error) {
				switch kind {
				case "lost response":
					return nil, core.ErrUnavailable
				case "wrong ID":
					return []core.Delivery{{ID: core.NewID(), Material: make([]byte, 32)}, {ID: ids[1], Material: make([]byte, 32)}}, nil
				case "crash":
					panic("simulated crash after consuming request")
				}
				return nil, nil
			}}
			r := open(t, c, p)
			func() {
				defer func() {
					if v := recover(); v != nil && kind != "crash" {
						panic(v)
					}
				}()
				if _, e := r.ConsumePeerKeys(pair, ids); e == nil {
					t.Fatal("uncertain batch delivered")
				}
			}()
			r.Close()
			r = open(t, c, p)
			if _, e := r.ConsumePeerKeys(pair, ids); e == nil || p.calls.Load() != 1 {
				t.Fatal("uncertain request retried")
			}
			for _, id := range ids {
				m, e := r.Metadata(id)
				if e != nil || m.SlaveState != core.Invalid {
					t.Fatal("uncertain ID not quarantined")
				}
			}
		})
	}
}

func TestExpiryCapacityAndFailedCommit(t *testing.T) {
	c := profile(t, "master")
	p := &fakeProvider{}
	r := open(t, c, p)
	now := time.Now()
	r.now = func() time.Time { return now }
	res, e := r.ReserveKeys(pair, 1)
	if e != nil {
		t.Fatal(e)
	}
	now = now.Add(61 * time.Second)
	if _, e = r.ConsumeReservation(pair, res.Token); e == nil {
		t.Fatal("expired reservation delivered")
	}
	m, e := r.Metadata(res.IDs[0])
	if e != nil || m.MasterState != core.Expired {
		t.Fatal("expiry not persisted")
	}
	res, e = r.ReserveKeys(pair, 1)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(c.StateDir, c.StateDir+"-away"); e != nil {
		t.Fatal(e)
	}
	if _, e = r.ConsumeReservation(pair, res.Token); e == nil {
		t.Fatal("failed durable commit exposed material")
	}
	if _, e = r.ReserveKeys(pair, 1); e == nil {
		t.Fatal("failed store remained usable")
	}
	c = profile(t, "master")
	p = &fakeProvider{allocate: func(int) ([]core.Delivery, error) { return nil, core.ErrUnavailable }}
	r, e = Open(c, pair, 1, p)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	_, _ = r.ReserveKeys(pair, 1)
	if _, e = r.ReserveKeys(pair, 1); !errors.Is(e, core.ErrCapacity) || p.calls.Load() != 1 {
		t.Fatal("uncertain attempts exceeded capacity")
	}
}

func TestBindingLockAndProviderCollision(t *testing.T) {
	c := profile(t, "master")
	p := &fakeProvider{}
	r := open(t, c, p)
	if other, e := Open(c, pair, 100, p); e == nil {
		other.Close()
		t.Fatal("second writer allowed")
	}
	res, e := r.ReserveKeys(pair, 1)
	if e != nil {
		t.Fatal(e)
	}
	p.allocate = func(int) ([]core.Delivery, error) {
		return []core.Delivery{{ID: res.IDs[0], Material: make([]byte, 32)}}, nil
	}
	if _, e = r.ReserveKeys(pair, 1); e == nil {
		t.Fatal("upstream collision replaced known ID")
	}
	keys, e := r.ConsumeReservation(pair, res.Token)
	if e != nil {
		t.Fatal("collision changed original reservation")
	}
	wipe(keys)
	r.Close()
	c.GatewaySlave = "WRONG-GATEWAY"
	if other, e := Open(c, pair, 100, p); e == nil {
		other.Close()
		t.Fatal("upstream association changed on restart")
	}
}
