package metadata

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
)

type memoryStore struct {
	raw             []byte
	fail            bool
	commitOnFailure bool
}

func (m *memoryStore) Save(b []byte) error {
	if !m.fail || m.commitOnFailure {
		m.raw = append([]byte(nil), b...)
	}
	if m.fail {
		return errors.New("injected persistence failure")
	}
	return nil
}
func (*memoryStore) Close() {}

type fixture struct {
	c        Config
	signing  *Signing
	inner    *memoryStore
	store    *Store
	now      time.Time
	keys     map[core.KeyID]Record
	attempts map[string]Attempt
}

func fixtureFor(t *testing.T, limit int) *fixture {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	sign, e := NewSigning(k, "test-signing-v1")
	if e != nil {
		t.Fatal(e)
	}
	z := int64(0)
	f := &fixture{signing: sign, inner: &memoryStore{}, now: time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC), keys: map[core.KeyID]Record{}, attempts: map[string]Attempt{}}
	f.c = Config{Domain: "test-domain", Issuer: "urn:test:node:a", Namespace: "test-pair", CredentialID: sign.kid, SigningKeyFile: "fixture", MaxEvents: limit, ClockUncertaintyMS: &z}
	f.store, _, e = Open(f.c, sign, f.inner, nil, fixtureProject, func() time.Time { return f.now })
	if e != nil {
		t.Fatal(e)
	}
	if e = f.save(); e != nil {
		t.Fatal(e)
	}
	return f
}

func fixtureProject(raw []byte) (Projection, error) {
	var p struct {
		Keys     map[core.KeyID]Record
		Attempts map[string]Attempt
	}
	e := json.Unmarshal(raw, &p)
	return Projection{Keys: p.Keys, Attempts: p.Attempts}, e
}
func (f *fixture) save() error {
	b, _ := json.Marshal(map[string]any{"Keys": f.keys, "Attempts": f.attempts, "Material": "SYNTHETIC-MATERIAL-MUST-NOT-ESCAPE"})
	return f.store.Save(b)
}
func (f *fixture) key() Record {
	return Record{Key: KeyRef{ID: core.NewID(), Association: core.Association{Master: "A", Slave: "B"}}, SourceClass: "synthetic", SourceEvidence: "local_observation", CollectionIntent: f.now.Add(-time.Hour), LocalExpiresAt: f.now.Add(time.Hour), Role: "local", MasterState: core.Available, SlaveState: core.Reserved, HoldingMaterial: true}
}
func (f *fixture) page(t *testing.T) SignedPage {
	t.Helper()
	p, e := f.store.Page("urn:test:auditor", []core.Association{{Master: "A", Slave: "B"}}, 0, 0, 64)
	if e != nil {
		t.Fatal(e)
	}
	return p
}

func TestAtomicHistoryRecoveryAndRedaction(t *testing.T) {
	f := fixtureFor(t, 100)
	r := f.key()
	f.keys[r.Key.ID] = r
	f.now = f.now.Add(time.Second)
	if e := f.save(); e != nil {
		t.Fatal(e)
	}
	r.MasterState = core.Consumed
	f.keys[r.Key.ID] = r
	f.now = f.now.Add(10 * time.Second)
	if e := f.save(); e != nil {
		t.Fatal(e)
	}
	p := f.page(t)
	if len(p.Page.Events) != 2 || p.Page.Events[1].Event.PreviousKeyEvent != p.Page.Events[0].Event.ID {
		t.Fatal("missing linked lifecycle events")
	}
	var decoded Page
	if e := verify(p.JWS, f.signing.public, f.signing.kid, &decoded, 256<<10); e != nil {
		t.Fatal("page signature", e)
	}
	public, _ := json.Marshal(p)
	if strings.Contains(string(public), "SYNTHETIC-MATERIAL") {
		t.Fatal("material escaped")
	}
	f.store.Close()
	reopened, raw, e := Open(f.c, f.signing, f.inner, append([]byte(nil), f.inner.raw...), fixtureProject, func() time.Time { return f.now })
	if e != nil {
		t.Fatal("recover", e)
	}
	if !durable.PlainSnapshot(raw) {
		t.Fatal("wrapper not removed")
	}
	clear(raw)
	after, e := reopened.Page("urn:test:auditor", p.Page.Scope, 0, 0, 64)
	if e != nil || !reflect.DeepEqual(p.Page, after.Page) {
		t.Fatal("history changed on recovery", e)
	}
	if durable.PlainSnapshot(f.inner.raw) {
		t.Fatal("unmanaged restart would erase metadata")
	}
}

func TestUncertainCommitWithholdsHistoryUntilRecovery(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_commit", true: "ambiguous_commit"}[commit], func(t *testing.T) {
			f := fixtureFor(t, 10)
			r := f.key()
			f.keys[r.Key.ID] = r
			if e := f.save(); e != nil {
				t.Fatal(e)
			}
			r.MasterState = core.Consumed
			f.keys[r.Key.ID] = r
			f.inner.fail = true
			f.inner.commitOnFailure = commit
			if f.save() == nil {
				t.Fatal("failed write accepted")
			}
			if _, e := f.store.Page("urn:test:auditor", []core.Association{r.Key.Association}, 0, 0, 10); e == nil {
				t.Fatal("poisoned store served stale history")
			}
			f.inner.fail = false
			recovered, raw, e := Open(f.c, f.signing, f.inner, append([]byte(nil), f.inner.raw...), fixtureProject, func() time.Time { return f.now })
			clear(raw)
			if e != nil {
				t.Fatal(e)
			}
			v, e := recovered.Key(r.Key.ID, "urn:test:a", "A", []core.Association{r.Key.Association})
			if e != nil {
				t.Fatal(e)
			}
			if (v.View.State == core.Consumed) != commit {
				t.Fatal("history not atomic with state")
			}
		})
	}
}

func TestHistoryCapacityClockAndBindingFailClosed(t *testing.T) {
	f := fixtureFor(t, 1)
	r := f.key()
	f.keys[r.Key.ID] = r
	if e := f.save(); e != nil {
		t.Fatal(e)
	}
	r.MasterState = core.Reserved
	f.keys[r.Key.ID] = r
	if f.save() == nil {
		t.Fatal("capacity ignored")
	}
	wrong := f.c
	wrong.Namespace = "other"
	if _, _, e := Open(wrong, f.signing, f.inner, append([]byte(nil), f.inner.raw...), fixtureProject, func() time.Time { return f.now }); e == nil {
		t.Fatal("rebound namespace")
	}
	if _, _, e := Open(f.c, f.signing, f.inner, []byte(`{"Keys":{}}`), fixtureProject, func() time.Time { return f.now }); e == nil {
		t.Fatal("invented history for old state")
	}
	f = fixtureFor(t, 10)
	f.now = f.now.Add(-time.Second)
	if f.save() == nil {
		t.Fatal("clock rollback ignored")
	}
}

func TestTamperAndTruncationRejectedOnRecovery(t *testing.T) {
	for _, kind := range []string{"record", "drop", "signature"} {
		t.Run(kind, func(t *testing.T) {
			f := fixtureFor(t, 10)
			r := f.key()
			f.keys[r.Key.ID] = r
			if e := f.save(); e != nil {
				t.Fatal(e)
			}
			var object map[string]json.RawMessage
			_ = json.Unmarshal(f.inner.raw, &object)
			var h history
			_ = json.Unmarshal(object[SnapshotField], &h)
			switch kind {
			case "record":
				h.Events[0].Event.Record.SourceClass = "satellite"
			case "drop":
				h.Events = nil
			case "signature":
				h.Events[0].JWS = "invalid"
			}
			object[SnapshotField], _ = json.Marshal(h)
			raw, _ := json.Marshal(object)
			if _, _, e := Open(f.c, f.signing, f.inner, raw, fixtureProject, func() time.Time { return f.now }); e == nil {
				t.Fatal("tampered history accepted")
			}
		})
	}
}

func TestAttemptAliasesNeverExposeReservationTokens(t *testing.T) {
	f := fixtureFor(t, 10)
	internal := string(core.NewID())
	f.attempts[internal] = Attempt{ID: internal, Association: core.Association{Master: "A", Slave: "B"}, Count: 1, Status: "pending", Started: f.now}
	if e := f.save(); e != nil {
		t.Fatal(e)
	}
	a := f.attempts[internal]
	a.Status = "uncertain"
	f.attempts[internal] = a
	if e := f.save(); e != nil {
		t.Fatal(e)
	}
	p := f.page(t)
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), internal) {
		t.Fatal("reservation token exposed")
	}
	first, last := p.Page.Events[0].Event.Attempt, p.Page.Events[1].Event.Attempt
	if first.Reference != last.Reference || len(last.IDs) != 0 || last.Status != "uncertain" {
		t.Fatal("lost unknown attempt correlation")
	}
}

func TestEvidenceVerificationScopeReplayAndRevocation(t *testing.T) {
	f := fixtureFor(t, 20)
	r := f.key()
	f.keys[r.Key.ID] = r
	if e := f.save(); e != nil {
		t.Fatal(e)
	}
	r.MasterState = core.Consumed
	f.keys[r.Key.ID] = r
	f.now = f.now.Add(time.Second)
	if e := f.save(); e != nil {
		t.Fatal(e)
	}
	der, _ := x509.MarshalPKIXPublicKey(f.signing.public)
	path := filepath.Join(t.TempDir(), "public.pem")
	if e := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	trust := []Trust{{Issuer: f.c.Issuer, Domain: f.c.Domain, Namespace: f.c.Namespace, CredentialID: f.c.CredentialID, PublicKeyFile: path, Pairs: []core.Association{r.Key.Association}, ValidFrom: f.now.Add(-time.Hour), ValidUntil: f.now.Add(time.Hour)}}
	p := f.page(t)
	events, c, e := VerifyPages([]SignedPage{p, p}, trust, "urn:test:auditor")
	if e != nil || len(events) != 2 || !c[0].Complete {
		t.Fatal("valid replay", e)
	}
	if _, _, e = VerifyPages([]SignedPage{p}, trust, "urn:test:other"); e == nil {
		t.Fatal("audience ignored")
	}
	altered := clone(p)
	altered.Page.Events[0].Event.Record.SourceClass = "satellite"
	if _, _, e = VerifyPages([]SignedPage{altered}, trust, "urn:test:auditor"); e == nil {
		t.Fatal("tamper accepted")
	}
	trust[0].Revoked = true
	if _, _, e = VerifyPages([]SignedPage{p}, trust, "urn:test:auditor"); e == nil {
		t.Fatal("revoked credential accepted")
	}
	trust[0].Revoked = false
	partial, err := f.store.Page("urn:test:auditor", p.Page.Scope, 1, p.Page.Watermark, 64)
	if err != nil {
		t.Fatal(err)
	}
	_, coverage, err := VerifyPages([]SignedPage{partial}, trust, "urn:test:auditor")
	if err != nil || coverage[0].Complete {
		t.Fatal("missing page treated as complete", err)
	}
	for _, kind := range []string{"state", "source", "delivery_action", "pair", "event_replay", "version", "algorithm", "clock_rollback"} {
		t.Run(kind, func(t *testing.T) {
			bad := clone(p)
			proof := &bad.Page.Events[1]
			switch kind {
			case "state":
				proof.Event.Record.MasterState = "UNSUPPORTED"
			case "source":
				proof.Event.Record.SourceClass = "satellite"
			case "delivery_action":
				proof.Event.Actions = []string{"slave_CONSUMED"}
			case "pair":
				proof.Event.Record.Key.Association.Slave = "C"
			case "event_replay":
				proof.Event.ID = bad.Page.Events[0].Event.ID
			case "version":
				proof.Event.Profile = "unsupported-v2"
			case "clock_rollback":
				bad.Page.Events[0].Event.RecordedAt = proof.Event.RecordedAt
				bad.Page.Events[0].JWS, _ = f.signing.Sign(bad.Page.Events[0].Event)
				proof.Event.PreviousDigest = checksum([]byte(bad.Page.Events[0].JWS))
				proof.Event.RecordedAt = proof.Event.RecordedAt.Add(-time.Second)
			}
			proof.JWS, _ = f.signing.Sign(proof.Event)
			if kind == "algorithm" {
				parts := strings.Split(proof.JWS, ".")
				parts[0] = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"test-signing-v1","typ":"transeuroogs-metadata+jws"}`))
				proof.JWS = strings.Join(parts, ".")
			}
			bad.JWS, _ = f.signing.Sign(bad.Page)
			if _, _, err := VerifyPages([]SignedPage{bad}, trust, "urn:test:auditor"); err == nil {
				t.Fatal("invalid signed evidence accepted")
			}
		})
	}
	trust[0].Namespace = "other"
	if _, _, e = VerifyPages([]SignedPage{p}, trust, "urn:test:auditor"); e == nil {
		t.Fatal("namespace authority ignored")
	}
}

func TestOversizedSnapshotFailsBeforeInnerCommit(t *testing.T) {
	f := fixtureFor(t, 10)
	before := append([]byte(nil), f.inner.raw...)
	if f.store.Save(make([]byte, MaxSnapshotBytes+1)) == nil || !reflect.DeepEqual(before, f.inner.raw) {
		t.Fatal("oversized snapshot reached persistence")
	}
	if f.save() == nil {
		t.Fatal("continued after oversized required event commit")
	}
}

func TestSigningCredentialPermissionsAndSeparation(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	defer clear(der)
	b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(b)
	path := filepath.Join(t.TempDir(), "metadata-signing.pem")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigning(path, "test"); err != nil {
		t.Fatal("separate test credential rejected", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigning(path, "test"); err == nil {
		t.Fatal("publicly readable signing credential accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "link.pem")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigning(link, "test"); err == nil {
		t.Fatal("symlink signing credential accepted")
	}
}
