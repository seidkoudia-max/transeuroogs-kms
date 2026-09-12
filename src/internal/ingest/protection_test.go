package ingest

import (
	"bytes"
	"crypto/ecdsa"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/federation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/storage"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testfederation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/upstream"
	"testing"
	"time"
)

type evidenceProvider struct {
	*fakeProvider
	config  *federation.Config
	signing *ecdsa.PrivateKey
	wrong   bool
	queries int
	outcome string
}

func TestRepositoryCannotBypassReviewedProviderContract(t *testing.T) {
	c := profile(t, "master")
	c.Profile, c.Agreement, c.EvidenceDir = upstream.FinalProfile, "synthetic-agreement", "test-evidence"
	f := testfederation.Config(pair)
	f.Pools[0].Gateways = core.Association{Master: c.GatewayMaster, Slave: c.GatewaySlave}
	for _, controls := range []*federation.Config{nil, f} {
		if r, e := OpenStoreControlled(c, pair, 10, &fakeProvider{}, &testallocation.Disk{}, nil, controls); e == nil {
			r.Close()
			t.Fatal("direct constructor bypassed required contract")
		}
	}
}

func (p *evidenceProvider) Evidence(ids []core.KeyID) (map[core.KeyID]string, error) {
	out := map[core.KeyID]string{}
	for _, id := range ids {
		v := testfederation.Evidence(p.config.Pools[0], id, time.Now().UTC())
		if p.wrong {
			v.Pool.Service = "wrong-service"
		}
		token, e := federation.SignEvidence(v, p.signing)
		if e != nil {
			return nil, e
		}
		out[id] = token
	}
	return out, nil
}
func (p *evidenceProvider) AllocateRequest(_ core.KeyID, n int) ([]core.Delivery, error) {
	return p.Allocate(n)
}
func (p *evidenceProvider) RetrieveRequest(_ core.KeyID, ids []core.KeyID) ([]core.Delivery, error) {
	return p.Retrieve(ids)
}
func (p *evidenceProvider) Outcome(core.KeyID) (string, error) { p.queries++; return p.outcome, nil }

func TestProviderEvidenceFailureReconciliationAndNeverRetry(t *testing.T) {
	for _, role := range []string{"master", "slave"} {
		t.Run(role, func(t *testing.T) {
			c := profile(t, role)
			f := testfederation.Config(pair)
			f.Pools[0].Gateways = core.Association{Master: c.GatewayMaster, Slave: c.GatewaySlave}
			f.Pools[0].RequireEvidence = true
			k, e := testfederation.Signing(f, time.Now())
			if e != nil {
				t.Fatal(e)
			}
			provider := &evidenceProvider{fakeProvider: &fakeProvider{}, config: f, signing: k, wrong: true, outcome: "not_consumed"}
			d := &testallocation.Disk{}
			r, e := OpenStoreControlled(c, pair, 10, provider, d, nil, f)
			if e != nil {
				t.Fatal(e)
			}
			id := core.NewID()
			if role == "master" {
				_, e = r.ReserveKeys(pair, 1)
			} else {
				_, e = r.ConsumePeerKeys(pair, []core.KeyID{id})
			}
			if e == nil {
				t.Fatal("wrong-service evidence delivered")
			}
			pending, e := r.PendingRequests(testfederation.Actor, f.Pools[0].Ref.ID)
			if e != nil || len(pending) != 1 || len(pending[0].KnownIDs) != 1 {
				t.Fatal("uncertainty not recorded", e)
			}
			action := core.NewID()
			result, e := r.Reconcile(testfederation.Actor, f.Pools[0].Ref.ID, action, pending[0].Reference)
			if e != nil || result.Status != "not_consumed" || provider.queries != 1 {
				t.Fatal("nonconsuming reconciliation", e)
			}
			r.Close()
			provider.wrong = false
			r, e = OpenStoreControlled(c, pair, 10, provider, d, bytes.Clone(d.Raw), f)
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			if _, e = r.Reconcile(testfederation.Actor, f.Pools[0].Ref.ID, action, pending[0].Reference); e != nil || provider.queries != 1 {
				t.Fatal("reconciliation replay", e)
			}
			m, e := r.Metadata(pending[0].KnownIDs[0])
			if e != nil || (role == "master" && m.MasterState != core.Invalid) || (role == "slave" && m.SlaveState != core.Invalid) {
				t.Fatal("reconciliation revived uncertain key", e)
			}
			if role == "slave" {
				if _, e = r.ConsumePeerKeys(pair, []core.KeyID{id}); e == nil || provider.calls.Load() != 1 {
					t.Fatal("uncertain key retried")
				}
			}
		})
	}
}

// Two independent final-key services model one local OGS reaching two remote
// OGSs. The provider owns pairing; national repositories never talk to each other.
func TestTwoRemotePoolsPreserveKIDsAndIndependentConsumption(t *testing.T) {
	for _, remote := range []string{"GR", "DE"} {
		t.Run(remote, func(t *testing.T) {
			a := core.Association{Master: "APP-LU", Slave: "APP-" + remote}
			f := testfederation.Config(a)
			f.Pools[0].Gateways = core.Association{Master: "GW-LU", Slave: "GW-GR"}
			f.Pools[0].Ref.Service = "LU-to-" + remote
			f.Pools[0].RequireEvidence = true
			key, e := testfederation.Signing(f, time.Now())
			if e != nil {
				t.Fatal(e)
			}
			paired, e := storage.NewMemory(10, nil)
			if e != nil {
				t.Fatal(e)
			}
			id := core.NewID()
			now := time.Now()
			if e = paired.StoreKey(core.Key{ID: id, Association: a, Material: bytes.Repeat([]byte{7}, 32), Source: "synthetic-qkd", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); e != nil {
				t.Fatal(e)
			}
			masterProvider := &evidenceProvider{fakeProvider: &fakeProvider{allocate: func(n int) ([]core.Delivery, error) {
				r, e := paired.ReserveKeys(a, n)
				if e != nil {
					return nil, e
				}
				return paired.ConsumeReservation(a, r.Token)
			}}, config: f, signing: key}
			masterConfig := profile(t, "master")
			master, e := OpenStoreControlled(masterConfig, a, 10, masterProvider, &testallocation.Disk{}, nil, f)
			if e != nil {
				t.Fatal(e)
			}
			other := federation.Clone(f)
			ref := other.Pools[0].Ref
			other.Pools[0].Ref.ID, other.Pools[0].Ref.RemoteID = ref.RemoteID, ref.ID
			other.Pools[0].Ref.Revision = 3
			other.Principals[testfederation.Actor] = federation.Grant{Pools: []string{other.Pools[0].Ref.ID}, Operate: true}
			slaveProvider := &evidenceProvider{fakeProvider: &fakeProvider{retrieve: func(ids []core.KeyID) ([]core.Delivery, error) { return paired.ConsumePeerKeys(a, ids) }}, config: other, signing: key}
			slave, e := OpenStoreControlled(profile(t, "slave"), a, 10, slaveProvider, &testallocation.Disk{}, nil, other)
			if e != nil {
				t.Fatal(e)
			}
			defer slave.Close()
			reserved, e := master.ReserveKeys(a, 1)
			if e != nil {
				t.Fatal(e)
			}
			left, e := master.ConsumeReservation(a, reserved.Token)
			if e != nil {
				t.Fatal(e)
			}
			master.Close()
			right, e := slave.ConsumePeerKeys(a, []core.KeyID{id})
			if e != nil || len(right) != 1 || left[0].ID != right[0].ID || !bytes.Equal(left[0].Material, right[0].Material) {
				t.Fatal("paired retrieval with master stopped", e)
			}
			wipe(left)
			wipe(right)
			if _, e = slave.ConsumePeerKeys(a, []core.KeyID{id}); e == nil {
				t.Fatal("slave replay")
			}
		})
	}
}
