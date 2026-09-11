// Package wrapping keeps encryption keys outside the lifecycle database.
package wrapping

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

var ErrKey = errors.New("wrapping service unavailable")
var name = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

type Protector interface {
	Seal([]byte, []byte) ([]byte, error)
	Open([]byte, []byte) ([]byte, error)
}

// PrivateRead rejects links, permissive modes and unbounded secret input.
func PrivateRead(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrKey
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || s.Size() > limit {
		return nil, ErrKey
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		clear(b)
		return nil, ErrKey
	}
	return b, nil
}

type FileRing struct{ Dir string }
type envelope struct {
	Version    int    `json:"version"`
	KeyID      string `json:"key_id"`
	Ciphertext []byte `json:"ciphertext"`
}

func (r FileRing) key(id string) (cipher.AEAD, error) {
	s, err := os.Lstat(r.Dir)
	if err != nil || !s.IsDir() || s.Mode().Perm() != 0700 || !name.MatchString(id) {
		return nil, ErrKey
	}
	k, err := PrivateRead(filepath.Join(r.Dir, id+".key"), 32)
	defer clear(k)
	if err != nil || len(k) != 32 {
		return nil, ErrKey
	}
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, ErrKey
	}
	return cipher.NewGCMWithRandomNonce(b)
}
func (r FileRing) Seal(raw, aad []byte) ([]byte, error) {
	b, err := PrivateRead(filepath.Join(r.Dir, "active"), 65)
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(string(b))
	a, err := r.key(id)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{1, id, a.Seal(nil, nil, raw, append([]byte("transeuroogs-state-v1:"+id+":"), aad...))})
}
func (r FileRing) Open(blob, aad []byte) ([]byte, error) {
	var e envelope
	if json.Unmarshal(blob, &e) != nil || e.Version != 1 {
		return nil, ErrKey
	}
	a, err := r.key(e.KeyID)
	if err != nil {
		return nil, err
	}
	raw, err := a.Open(nil, nil, e.Ciphertext, append([]byte("transeuroogs-state-v1:"+e.KeyID+":"), aad...))
	if err != nil {
		return nil, ErrKey
	}
	return raw, nil
}
