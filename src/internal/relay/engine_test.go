package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/etsi020"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/peering"
)

var association = core.Association{Master: "SAE-LU", Slave: "SAE-GR"}

type network struct {
	nodes             map[string]*Engine
	down              map[string]bool
	loseSend, loseAck bool
	sends             map[string]int
}
type link struct {
	n    *network
	from string
}

func (l link) Probe(_ context.Context, to string) error {
	if l.n.down[to] {
		return core.ErrUnavailable
	}
	return nil
}
func (l link) Send(_ context.Context, to string, t etsi020.Transfer) error {
	l.n.sends[l.from+">"+to]++
	if l.n.down[to] {
		return core.ErrUnavailable
	}
	err := l.n.nodes[to].Accept(l.from, t)
	if l.n.loseSend {
		l.n.loseSend = false
		return core.ErrUnavailable
	}
	return err
}
func (l link) Ack(_ context.Context, to string, a []etsi020.Ack) error {
	if l.n.down[to] {
		return core.ErrUnavailable
	}
	err := l.n.nodes[to].Acknowledge(l.from, a)
	if l.n.loseAck {
		l.n.loseAck = false
		return core.ErrUnavailable
	}
	return err
}
func (l link) Void(_ context.Context, to string, v etsi020.Void) error {
	if l.n.down[to] {
		return core.ErrUnavailable
	}
	return l.n.nodes[to].Void(l.from, v)
}

func setup(t *testing.T, multipath bool) *network {
	t.Helper()
	n := &network{nodes: map[string]*Engine{}, down: map[string]bool{}, sends: map[string]int{}}
	routes := map[string][]string{"lu": {"gr"}, "gr": nil}
	if multipath {
		routes = map[string][]string{"lu": {"eagle-lu"}, "eagle-lu": {"relay-a", "relay-b"}, "relay-a": {"eagle-gr"}, "relay-b": {"eagle-gr"}, "eagle-gr": {"gr"}, "gr": nil}
	}
	for name, next := range routes {
		cfg := peering.Config{PublicURL: "https://" + name, Identity: "urn:kme:" + name, StateDir: filepath.Join(t.TempDir(), "state"), Peers: map[string]peering.Peer{}, Routes: map[string][]string{}, TargetKMEs: map[string]string{"SAE-GR": "gr"}}
		if name == "lu" {
			cfg.LocalSAEs = []string{"SAE-LU"}
		}
		if name == "gr" {
			cfg.LocalSAEs = []string{"SAE-GR"}
		}
		if len(next) > 0 {
			cfg.Routes["SAE-GR"] = next
		}
		for _, to := range next {
			cfg.Peers[to] = peering.Peer{URL: "https://" + to, Identity: "urn:kme:" + to, Mode: peering.Standard}
		}
		for from, outs := range routes {
			for _, to := range outs {
				if to == name {
					cfg.Peers[from] = peering.Peer{URL: "https://" + from, Identity: "urn:kme:" + from, Mode: peering.Standard, Incoming: true}
				}
			}
		}
		e, err := Open(cfg, []core.Association{association}, 1000, link{n, name})
		if err != nil {
			t.Fatal(err)
		}
		e.retry = 0
		n.nodes[name] = e
	}
	t.Cleanup(func() {
		for _, e := range n.nodes {
			e.Close()
		}
	})
	return n
}
func (n *network) pump(rounds int) {
	for range rounds {
		for name, e := range n.nodes {
			if !n.down[name] {
				e.Step(context.Background())
			}
		}
	}
}
func seed(t *testing.T, e *Engine, count int) []core.Key {
	t.Helper()
	out := make([]core.Key, count)
	for i := range out {
		out[i] = core.Key{ID: core.NewID(), Association: association, Material: bytes.Repeat([]byte{byte(i + 1)}, 32), Source: "synthetic", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
		if err := e.StoreKey(out[i]); err != nil {
			t.Fatal(err)
		}
	}
	return out
}
func consume(t *testing.T, n *network, count int) []core.Delivery {
	t.Helper()
	res, err := n.nodes["lu"].ReserveKeys(association, count)
	if err != nil {
		t.Fatal(err)
	}
	master, err := n.nodes["lu"].ConsumeReservation(association, res.Token)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := n.nodes["gr"].ConsumePeerKeys(association, res.IDs)
	if err != nil {
		t.Fatal(err)
	}
	for i := range master {
		if master[i].ID != peer[i].ID || !bytes.Equal(master[i].Material, peer[i].Material) {
			t.Fatal("recipient keys differ")
		}
	}
	return master
}
func reopen(t *testing.T, n *network, name string) {
	t.Helper()
	old := n.nodes[name]
	cfg := old.cfg
	old.Close()
	e, err := Open(cfg, []core.Association{association}, 1000, link{n, name})
	if err != nil {
		t.Fatal(err)
	}
	e.retry = 0
	n.nodes[name] = e
}

func TestMultipathEndToEndAndRestart(t *testing.T) {
	n := setup(t, true)
	keys := seed(t, n.nodes["lu"], 12)
	if _, err := n.nodes["lu"].ReserveKeys(association, 1); !errors.Is(err, core.ErrUnavailable) {
		t.Fatal("source released before destination ACK")
	}
	n.pump(15)
	paths := n.nodes["eagle-lu"].Snapshot().Paths
	if paths["relay-a"] != 6 || paths["relay-b"] != 6 {
		t.Fatalf("distinct-key path distribution: %v", paths)
	}
	for _, name := range []string{"eagle-lu", "relay-a", "relay-b", "eagle-gr"} {
		for _, r := range n.nodes[name].s.Keys {
			if len(r.Material) != 0 {
				t.Fatal("intermediate retained acknowledged key")
			}
		}
	}
	consume(t, n, 12)
	reopen(t, n, "lu")
	reopen(t, n, "gr")
	if n.nodes["lu"].Inventory(association).Available != 0 {
		t.Fatal("restart revived source")
	}
	if _, err := n.nodes["gr"].ConsumePeerKeys(association, []core.KeyID{keys[0].ID}); !errors.Is(err, core.ErrUnavailable) {
		t.Fatal("restart revived target")
	}
}
func TestPreflightFailoverAndUncertainTransferPinned(t *testing.T) {
	n := setup(t, true)
	n.down["relay-a"] = true
	seed(t, n.nodes["lu"], 4)
	n.pump(12)
	if paths := n.nodes["eagle-lu"].Snapshot().Paths; paths["relay-b"] != 4 || paths["relay-a"] != 0 {
		t.Fatal(paths)
	}
	consume(t, n, 4)
	// A response lost after acceptance is uncertain: never send this ID on B.
	n.down["relay-a"] = false
	seed(t, n.nodes["lu"], 1)
	n.nodes["lu"].Step(context.Background())
	n.loseSend = true
	n.nodes["eagle-lu"].Step(context.Background())
	n.down["relay-a"] = true
	reopen(t, n, "eagle-lu")
	n.pump(4)
	if n.nodes["lu"].Inventory(association).Available != 0 {
		t.Fatal("uncertain key became ready")
	}
	if n.nodes["eagle-lu"].Snapshot().Paths["relay-b"] != 4 {
		t.Fatal("ambiguous transfer failed over")
	}
	n.down["relay-a"] = false
	n.loseAck = true
	n.pump(15)
	consume(t, n, 1)
}
func TestLostAcknowledgementOutboxSurvivesRestart(t *testing.T) {
	n := setup(t, false)
	seed(t, n.nodes["lu"], 1)
	n.nodes["lu"].Step(context.Background())
	n.down["lu"] = true
	n.nodes["gr"].Step(context.Background())
	reopen(t, n, "gr")
	if n.nodes["gr"].Snapshot().PendingAcks != 1 {
		t.Fatal("lost durable ACK")
	}
	n.down["lu"] = false
	n.pump(5)
	consume(t, n, 1)
}
func transfer(k core.Key, from string) etsi020.Transfer {
	return etsi020.Transfer{Keys: []etsi020.Key{{ID: k.ID, Value: base64.StdEncoding.EncodeToString(k.Material)}}, Initiator: association.Master, Targets: []string{association.Slave}, Callback: "https://" + from + "/kmapi/v1/ext_keys/ack"}
}
func TestAtomicConflictDuplicateAndPartialAcknowledgements(t *testing.T) {
	n := setup(t, false)
	keys := seed(t, n.nodes["lu"], 2)
	target := n.nodes["gr"]
	one := transfer(keys[0], "lu")
	if err := target.Accept("lu", one); err != nil {
		t.Fatal(err)
	}
	bad := transfer(keys[1], "lu")
	conflict := one.Keys[0]
	conflict.Value = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{99}, 32))
	bad.Keys = append(bad.Keys, conflict)
	if !errors.Is(target.Accept("lu", bad), core.ErrDuplicate) {
		t.Fatal("conflicting material accepted")
	}
	if target.Snapshot().Records != 1 {
		t.Fatal("partial batch persisted")
	}
	n.nodes["lu"].Step(context.Background())
	a := etsi020.Ack{IDs: []etsi020.KeyRef{{ID: keys[0].ID}}, Status: "relayed", Initiator: association.Master, Targets: []string{association.Slave}}
	if err := n.nodes["lu"].Acknowledge("gr", []etsi020.Ack{a}); err != nil {
		t.Fatal(err)
	}
	if n.nodes["lu"].Inventory(association).Available != 1 {
		t.Fatal("partial ACK released other key")
	}
	if _, err := target.ConsumePeerKeys(association, []core.KeyID{keys[0].ID}); err != nil {
		t.Fatal(err)
	}
	if err := target.Accept("lu", one); err != nil {
		t.Fatal(err)
	}
	if _, err := target.ConsumePeerKeys(association, []core.KeyID{keys[0].ID}); !errors.Is(err, core.ErrUnavailable) {
		t.Fatal("duplicate transfer revived consumption")
	}
}
func TestVoidPropagationLateAckUnknownAndConsumed(t *testing.T) {
	n := setup(t, true)
	keys := seed(t, n.nodes["lu"], 2)
	n.pump(15)
	consume(t, n, 1)
	if err := n.nodes["lu"].InvalidateKey(keys[1].ID); err != nil {
		t.Fatal(err)
	}
	n.pump(15)
	if _, err := n.nodes["gr"].ConsumePeerKeys(association, []core.KeyID{keys[1].ID}); !errors.Is(err, core.ErrUnavailable) {
		t.Fatal("void did not reach target")
	}
	late := etsi020.Ack{IDs: []etsi020.KeyRef{{ID: keys[1].ID}}, Status: "relayed", Initiator: association.Master, Targets: []string{association.Slave}}
	if err := n.nodes["lu"].Acknowledge("eagle-lu", []etsi020.Ack{late}); err != nil {
		t.Fatal(err)
	}
	if n.nodes["lu"].Inventory(association).Available != 0 {
		t.Fatal("late ACK revived voided key")
	}
	if err := n.nodes["lu"].InvalidateKey(keys[0].ID); err != nil {
		t.Fatal(err)
	}
	n.pump(15)
	if !n.nodes["lu"].s.Keys[keys[0].ID].VoidFailed {
		t.Fatal("claimed to recall a consumed key")
	}
	direct := setup(t, false)
	k := seed(t, direct.nodes["lu"], 1)[0]
	v := etsi020.Void{IDs: []core.KeyID{k.ID}, Initiator: association.Master, Targets: []string{association.Slave}, Callback: "https://lu/kmapi/v1/ext_keys/ack"}
	if err := direct.nodes["gr"].Void("lu", v); err != nil {
		t.Fatal(err)
	}
	if err := direct.nodes["gr"].Accept("lu", transfer(k, "lu")); err != nil {
		t.Fatal(err)
	}
	if _, err := direct.nodes["gr"].ConsumePeerKeys(association, []core.KeyID{k.ID}); !errors.Is(err, core.ErrUnavailable) {
		t.Fatal("late transfer defeated void tombstone")
	}
}
func TestExpiryAndConcurrentSingleDelivery(t *testing.T) {
	n := setup(t, false)
	keys := seed(t, n.nodes["lu"], 2)
	n.pump(4)
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for range 16 {
		wg.Go(func() {
			_, err := n.nodes["gr"].ConsumePeerKeys(association, []core.KeyID{keys[0].ID})
			if err == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if success != 1 {
		t.Fatal("concurrent duplicate delivery")
	}
	n.nodes["lu"].now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	n.pump(8)
	if _, err := n.nodes["gr"].ConsumePeerKeys(association, []core.KeyID{keys[1].ID}); !errors.Is(err, core.ErrUnavailable) {
		t.Fatal("expiry did not propagate void")
	}
}
func TestOptionalExtensionsPreservedAndOwned(t *testing.T) {
	n := setup(t, true)
	k := seed(t, n.nodes["lu"], 1)[0]
	tr := transfer(k, "lu")
	tr.Optional = etsi020.Extension{"E32473_fixture": json.RawMessage(`{"opaque":[null,1,"keep"]}`)}
	if err := n.nodes["eagle-lu"].Accept("lu", tr); err != nil {
		t.Fatal(err)
	}
	tr.Optional["E32473_fixture"][0] = '!'
	n.nodes["eagle-lu"].Step(context.Background())
	for _, name := range []string{"relay-a", "relay-b"} {
		if r := n.nodes[name].s.Keys[k.ID]; r != nil && string(r.Optional["E32473_fixture"]) != `{"opaque":[null,1,"keep"]}` {
			t.Fatal("optional extension changed")
		}
	}
}
func TestJournalLockCorruptionMissingStateAndFailClosed(t *testing.T) {
	for _, fault := range []string{"corrupt", "missing", "wrong-key"} {
		t.Run(fault, func(t *testing.T) {
			n := setup(t, false)
			e := n.nodes["lu"]
			keys := seed(t, e, 1)
			if _, err := Open(e.cfg, []core.Association{association}, 1000, link{n, "lu"}); err == nil {
				t.Fatal("two writers opened same state")
			}
			data, err := os.ReadFile(filepath.Join(e.cfg.StateDir, "state.enc"))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, keys[0].Material) || bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(keys[0].Material))) {
				t.Fatal("plaintext state")
			}
			e.Close()
			switch fault {
			case "corrupt":
				err = os.WriteFile(filepath.Join(e.cfg.StateDir, "state.enc"), []byte("bad"), 0600)
			case "missing":
				err = os.Remove(filepath.Join(e.cfg.StateDir, "state.enc"))
			case "wrong-key":
				err = os.WriteFile(filepath.Join(e.cfg.StateDir, "wrapping.key"), bytes.Repeat([]byte{7}, 32), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Open(e.cfg, []core.Association{association}, 1000, link{n, "lu"}); err == nil {
				t.Fatal("corrupt state silently reset")
			}
		})
	}
	n := setup(t, false)
	seed(t, n.nodes["lu"], 1)
	n.pump(4)
	e := n.nodes["lu"]
	e.j.dir = filepath.Join(t.TempDir(), "missing")
	if _, err := e.ReserveKeys(association, 1); err == nil {
		t.Fatal("disk failure accepted")
	}
	if e.Inventory(association).Available != 0 {
		t.Fatal("failed journal continued serving")
	}
}
