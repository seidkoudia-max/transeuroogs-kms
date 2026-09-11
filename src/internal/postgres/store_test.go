package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/storage"
)

func configForTest(t *testing.T) Config {
	t.Helper()
	dsn := os.Getenv("KMS_TEST_DSN")
	if dsn == "" {
		t.Skip("KMS_TEST_DSN required for real PostgreSQL acceptance")
	}
	d := t.TempDir()
	os.Chmod(d, 0700)
	keydir := filepath.Join(d, "keys")
	os.Mkdir(keydir, 0700)
	os.WriteFile(filepath.Join(keydir, "v1.key"), bytes.Repeat([]byte{3}, 32), 0600)
	os.WriteFile(filepath.Join(keydir, "active"), []byte("v1"), 0600)
	p := filepath.Join(d, "dsn")
	os.WriteFile(p, []byte(dsn), 0600)
	c := Config{DSNFile: p, Namespace: string(core.NewID()), CheckpointDir: filepath.Join(d, "checkpoint"), WrappingKeyDir: keydir, AllowLocalSocket: true}
	if err := Migrate(c); err != nil {
		t.Fatal(err)
	}
	return c
}
func openLocal(t *testing.T, c Config, init bool) (*Store, *storage.Persistent) {
	t.Helper()
	s, b, e := Open(c, init)
	if e != nil {
		t.Fatal("open", e)
	}
	r, e := storage.OpenPersistent(100, "test-binding", s, b)
	if e != nil {
		t.Fatal("repository", e)
	}
	return s, r
}
func TestPostgresLifecycleIsolationRestartAndFencing(t *testing.T) {
	c := configForTest(t)
	s, r := openLocal(t, c, true)
	defer r.Close()
	if other, _, e := Open(c, false); e == nil {
		other.Close()
		t.Fatal("second writer acquired namespace")
	}
	a := core.Association{Master: "A", Slave: "B"}
	k := core.Key{ID: core.NewID(), Association: a, Material: bytes.Repeat([]byte{19}, 32), Source: "synthetic", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if e := r.StoreKey(k); e != nil {
		t.Fatal(e)
	}
	if e := r.StoreKey(k); e != core.ErrDuplicate {
		t.Fatal("duplicate accepted")
	}
	res, e := r.ReserveKeys(a, 1)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var wins atomic.Int32
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, e := r.ConsumeReservation(a, res.Token)
			if e == nil {
				wins.Add(1)
				if len(d) != 1 || !bytes.Equal(d[0].Material, k.Material) {
					t.Error("wrong delivery")
				}
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("non-atomic reservation")
	}
	var meta, blob []byte
	if e = s.conn.QueryRow(context.Background(), `SELECT metadata,ciphertext FROM kms_meta.state JOIN kms_secret.state USING(namespace) WHERE namespace=$1`, c.Namespace).Scan(&meta, &blob); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(meta, []byte("Material")) || bytes.Contains(meta, []byte(base64.StdEncoding.EncodeToString(k.Material))) || bytes.Contains(blob, k.Material) {
		t.Fatal("material leaked into metadata/plaintext")
	}
	r.Close()
	s, r = openLocal(t, c, false)
	defer r.Close()
	if _, e = r.ConsumeReservation(a, res.Token); e == nil {
		t.Fatal("master replay after restart")
	}
	if _, e = r.ConsumePeerKeys(core.Association{Master: "C", Slave: "B"}, []core.KeyID{k.ID}); e != core.ErrUnauthorized {
		t.Fatal("association bypass")
	}
	d, e := r.ConsumePeerKeys(a, []core.KeyID{k.ID})
	if e != nil || !bytes.Equal(d[0].Material, k.Material) {
		t.Fatal("peer delivery lost")
	}
	if _, e = r.ConsumePeerKeys(a, []core.KeyID{k.ID}); e == nil {
		t.Fatal("peer replay")
	}
	var count int
	if e = s.conn.QueryRow(context.Background(), `SELECT count(*) FROM kms_audit.events WHERE namespace=$1`, c.Namespace).Scan(&count); e != nil || count < 5 {
		t.Fatal("missing transition audit")
	}
}
func TestPostgresRejectsDatabaseRollback(t *testing.T) {
	c := configForTest(t)
	s, r := openLocal(t, c, true)
	admin, e := connection(c)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close(context.Background())
	var version int64
	var meta, blob []byte
	admin.QueryRow(context.Background(), `SELECT version,metadata,ciphertext FROM kms_meta.state JOIN kms_secret.state USING(namespace) WHERE namespace=$1`, c.Namespace).Scan(&version, &meta, &blob)
	if e = s.Save([]byte(`{"Keys":{}}`)); e != nil {
		t.Fatal(e)
	}
	r.Close()
	if _, e = admin.Exec(context.Background(), `UPDATE kms_meta.state SET version=$1,metadata=$2 WHERE namespace=$3`, version, meta, c.Namespace); e != nil {
		t.Fatal(e)
	}
	admin.Exec(context.Background(), `UPDATE kms_secret.state SET ciphertext=$1 WHERE namespace=$2`, blob, c.Namespace)
	if p, _, e := Open(c, false); e == nil {
		p.Close()
		t.Fatal("old database snapshot accepted")
	}
}
func TestPostgresLostConnectionFailsClosed(t *testing.T) {
	c := configForTest(t)
	s, r := openLocal(t, c, true)
	defer r.Close()
	a := core.Association{Master: "A", Slave: "B"}
	k := core.Key{ID: core.NewID(), Association: a, Material: bytes.Repeat([]byte{2}, 32), Source: "synthetic", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if e := r.StoreKey(k); e != nil {
		t.Fatal(e)
	}
	res, e := r.ReserveKeys(a, 1)
	if e != nil {
		t.Fatal(e)
	}
	s.conn.Close(context.Background())
	if d, e := r.ConsumeReservation(a, res.Token); e == nil || len(d) != 0 {
		t.Fatal("delivery despite failed commit")
	}
	if d, e := r.ConsumeReservation(a, res.Token); e == nil || len(d) != 0 {
		t.Fatal("failed process resumed")
	}
}
func TestPublicMetadataExcludesArbitraryExtensions(t *testing.T) {
	id := string(core.NewID())
	raw, _ := json.Marshal(map[string]any{"Keys": map[string]any{id: map[string]any{"Material": "secret", "Digest": "fingerprint", "Optional": map[string]any{"key": "secret"}, "State": "RESERVED"}}})
	meta, e := publicMetadata(raw)
	if e != nil || bytes.Contains(meta, []byte("secret")) || bytes.Contains(meta, []byte("fingerprint")) {
		t.Fatal("secret field exposed")
	}
}

func TestRuntimeAndObserverDatabasePrivileges(t *testing.T) {
	c := configForTest(t)
	s, r := openLocal(t, c, true)
	defer r.Close()
	admin, err := connection(c)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	ctx := context.Background()
	// Names contain only a fixed prefix and UUID hex; no user SQL is interpolated.
	runtime := "runtime_" + strings.ReplaceAll(string(core.NewID()), "-", "")
	observer := "observer_" + strings.ReplaceAll(string(core.NewID()), "-", "")
	for _, role := range []string{runtime, observer} {
		if _, err = admin.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
			t.Fatal(err)
		}
	}
	for _, sql := range []string{
		"GRANT USAGE ON SCHEMA kms_meta,kms_secret,kms_audit TO " + runtime,
		"GRANT SELECT,INSERT,UPDATE ON kms_meta.state,kms_secret.state TO " + runtime,
		"GRANT INSERT ON kms_audit.events TO " + runtime,
		"GRANT USAGE ON ALL SEQUENCES IN SCHEMA kms_audit TO " + runtime,
		"GRANT USAGE ON SCHEMA kms_meta,kms_audit TO " + observer,
		"GRANT SELECT ON kms_meta.state,kms_audit.events TO " + observer,
	} {
		if _, err = admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.conn.Exec(ctx, "SET ROLE "+runtime); err != nil {
		t.Fatal(err)
	}
	if err = s.Save([]byte(`{"Keys":{}}`)); err != nil {
		t.Fatal("runtime cannot commit", err)
	}
	if err = s.Record(string(core.NewID()), "urn:test:actor", "enc_keys", "intent", 0); err != nil {
		t.Fatal(err)
	}
	if _, err = s.conn.Exec(ctx, "DELETE FROM kms_audit.events"); err == nil {
		t.Fatal("runtime can delete audit")
	}
	if _, err = s.conn.Exec(ctx, "UPDATE kms_audit.events SET status=200"); err == nil {
		t.Fatal("runtime can edit audit")
	}
	if _, err = admin.Exec(ctx, "SET ROLE "+observer); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, "SELECT metadata FROM kms_meta.state"); err != nil {
		t.Fatal("observer cannot read metadata")
	}
	if _, err = admin.Exec(ctx, "SELECT ciphertext FROM kms_secret.state"); err == nil {
		t.Fatal("observer can read key material schema")
	}
}
