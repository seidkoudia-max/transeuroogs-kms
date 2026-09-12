package relay

import (
	"bytes"
	"context"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/etsi020"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/peering"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"testing"
	"time"
)

type policyTransport struct {
	probe func(string)
	sends []string
}

func (p *policyTransport) Probe(_ context.Context, peer string) error {
	if p.probe != nil {
		p.probe(peer)
	}
	return nil
}
func (p *policyTransport) Send(_ context.Context, peer string, _ etsi020.Transfer) error {
	p.sends = append(p.sends, peer)
	return core.ErrUnavailable
}
func (*policyTransport) Ack(context.Context, string, []etsi020.Ack) error { return nil }
func (*policyTransport) Void(context.Context, string, etsi020.Void) error { return nil }
func TestRouteChangeDuringProbeAndPinnedIntentAfterRestart(t *testing.T) {
	cfg := peering.Config{PublicURL: "https://local", Identity: "urn:test:local", StateDir: "unused", LocalSAEs: []string{association.Master}, TargetKMEs: map[string]string{association.Slave: "target"}, Routes: map[string][]string{association.Slave: {"one", "two"}}, Peers: map[string]peering.Peer{
		"one": {URL: "https://one", Identity: "urn:test:one", Mode: peering.Standard}, "two": {URL: "https://two", Identity: "urn:test:two", Mode: peering.Standard},
	}}
	setup := testallocation.Setup(association)
	d := &testallocation.Disk{}
	transport := &policyTransport{}
	e, err := OpenStore(cfg, []core.Association{association}, 10, transport, d, nil, setup)
	if err != nil {
		t.Fatal(err)
	}
	e.retry = 0
	keys := seed(t, e, 2)
	command := allocation.Command{ID: core.NewID(), ExpectedRevision: 0, Association: association, Routes: []string{"two"}}
	transport.probe = func(string) {
		transport.probe = nil
		if _, err = e.ApplyCommand(testallocation.Actor, command); err != nil {
			t.Fatal(err)
		}
	}
	e.sendRecord(context.Background(), keys[0].ID)
	if len(transport.sends) != 0 {
		t.Fatal("removed route survived probe race")
	}
	e.sendRecord(context.Background(), keys[0].ID)
	if len(transport.sends) != 1 || transport.sends[0] != "two" {
		t.Fatal("new route unused")
	}
	command = allocation.Command{ID: core.NewID(), ExpectedRevision: 1, Association: association, Routes: []string{"one"}}
	if _, err = e.ApplyCommand(testallocation.Actor, command); err != nil {
		t.Fatal(err)
	}
	e.Close()
	e, err = OpenStore(cfg, []core.Association{association}, 10, transport, d, bytes.Clone(d.Raw), setup)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.retry = 0
	e.sendRecord(context.Background(), keys[0].ID)
	e.sendRecord(context.Background(), keys[1].ID)
	if len(transport.sends) != 3 || transport.sends[1] != "two" || transport.sends[2] != "one" {
		t.Fatal("committed key migrated or unsent key not rerouted", transport.sends)
	}
	forged := allocation.Command{ID: core.NewID(), ExpectedRevision: 2, Association: association, Routes: []string{"https://attacker"}}
	if _, err = e.ApplyCommand(testallocation.Actor, forged); err == nil {
		t.Fatal("route catalog bypass")
	}
}
func TestRelayRechecksDeliveryPolicy(t *testing.T) {
	n := setup(t, false)
	e := n.nodes["lu"]
	cfg := e.cfg
	e.Close()
	policy := testallocation.Setup(association)
	d := &testallocation.Disk{}
	var err error
	e, err = OpenStore(cfg, []core.Association{association}, 1000, link{n, "lu"}, d, nil, policy)
	if err != nil {
		t.Fatal(err)
	}
	n.nodes["lu"] = e
	e.retry = 0
	seed(t, e, 2)
	n.pump(5)
	res, err := e.ReserveKeys(association, 2)
	if err != nil {
		t.Fatal(err)
	}
	rule := testallocation.Rule()
	rule.Paused = true
	if _, err = e.ApplyCommand(testallocation.Actor, testallocation.Command(association, 0, rule)); err != nil {
		t.Fatal(err)
	}
	if _, err = e.ConsumeReservation(association, res.Token); err == nil {
		t.Fatal("relay escaped pause")
	}
	rule.Paused = false
	rule.MaxLocalAgeSeconds = 1
	if _, err = e.ApplyCommand(testallocation.Actor, testallocation.Command(association, 1, rule)); err != nil {
		t.Fatal(err)
	}
	e.now = func() time.Time { return time.Now().Add(2 * time.Second) }
	if _, err = e.ConsumeReservation(association, res.Token); err == nil {
		t.Fatal("relay escaped freshness check")
	}
}
