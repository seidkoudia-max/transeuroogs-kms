package wrapping

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyRotationAndBinding(t *testing.T) {
	d := t.TempDir()
	os.Chmod(d, 0700)
	for _, id := range []string{"old", "new"} {
		if err := os.WriteFile(filepath.Join(d, id+".key"), bytes.Repeat([]byte(id[:1]), 32), 0600); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(d, "active"), []byte("old"), 0600)
	r := FileRing{d}
	raw := bytes.Repeat([]byte{77}, 32)
	b, e := r.Seal(raw, []byte("one"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Open(b, []byte("two")); e == nil {
		t.Fatal("cross-namespace ciphertext accepted")
	}
	os.WriteFile(filepath.Join(d, "active"), []byte("new"), 0600)
	out, e := r.Open(b, []byte("one"))
	if e != nil || !bytes.Equal(raw, out) {
		t.Fatal("old generation unavailable")
	}
	newBlob, e := r.Seal(raw, []byte("one"))
	if e != nil || bytes.Equal(b, newBlob) {
		t.Fatal("rotation failed")
	}
	os.Chmod(filepath.Join(d, "new.key"), 0644)
	if _, e = r.Open(newBlob, []byte("one")); e == nil {
		t.Fatal("permissive secret accepted")
	}
}
