package durable

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestContextBindingAndClosedWriter(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j, _, err := Open(dir, "context-A")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("synthetic snapshot")
	if err = j.Save(data); err != nil {
		t.Fatal(err)
	}
	j.Close()
	if err = j.Save([]byte("must not replace snapshot")); err == nil {
		t.Fatal("closed writer saved state")
	}
	if other, _, err := Open(dir, "context-B"); err == nil {
		other.Close()
		t.Fatal("wrong context decrypted state")
	}
	j, raw, err := Open(dir, "context-A")
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	defer clear(raw)
	if !bytes.Equal(data, raw) {
		t.Fatal("failed open/write changed saved state")
	}
}
