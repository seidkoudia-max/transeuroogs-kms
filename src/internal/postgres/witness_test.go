package postgres

import (
	"context"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/witness"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/wrapping"
	"os"
	"path/filepath"
	"testing"
)

func TestWitnessRejectsCombinedDatabaseAndLocalCheckpointRollback(t *testing.T) {
	c := configForTest(t)
	authority, e := witness.Open(&testallocation.Disk{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer authority.Close()
	p := wrapping.FileRing{Dir: c.WrappingKeyDir}
	s, _, e := OpenWitnessed(c, true, p, authority)
	if e != nil {
		t.Fatal("initial witnessed store", e)
	}
	admin, e := connection(c)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close(context.Background())
	var version int64
	var meta, blob []byte
	if e = admin.QueryRow(context.Background(), `SELECT version,metadata,ciphertext FROM kms_meta.state JOIN kms_secret.state USING(namespace) WHERE namespace=$1`, c.Namespace).Scan(&version, &meta, &blob); e != nil {
		t.Fatal(e)
	}
	checkpointFile := filepath.Join(c.CheckpointDir, "state.enc")
	old, e := os.ReadFile(checkpointFile)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Save([]byte(`{"Keys":{}}`)); e != nil {
		t.Fatal(e)
	}
	s.Close()
	if unguarded, _, e := OpenProtected(c, false, p); e == nil {
		unguarded.Close()
		t.Fatal("witness silently disabled")
	}
	if _, e = admin.Exec(context.Background(), `UPDATE kms_meta.state SET version=$1,metadata=$2 WHERE namespace=$3`, version, meta, c.Namespace); e != nil {
		t.Fatal(e)
	}
	if _, e = admin.Exec(context.Background(), `UPDATE kms_secret.state SET ciphertext=$1 WHERE namespace=$2`, blob, c.Namespace); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(checkpointFile, old, 0600); e != nil {
		t.Fatal(e)
	}
	if restored, _, e := OpenWitnessed(c, false, p, authority); e == nil {
		restored.Close()
		t.Fatal("combined rollback bypassed independent witness")
	}
}
