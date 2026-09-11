// Package relay implements durable, trusted-node key distribution. The lab
// transport is classical mTLS; it does not claim QKD link encryption.
package relay

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type journal struct {
	dir  string
	lock *os.File
	aead cipher.AEAD
}

var errJournal = errors.New("durable key state unavailable; recovery required")

func openJournal(dir string) (j *journal, raw []byte, err error) {
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, errJournal
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, nil, errJournal
	}
	lock, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, nil, errJournal
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		lock.Close()
		return nil, nil, errJournal
	}
	j = &journal{dir: dir, lock: lock}
	defer func() {
		if err != nil {
			j.close()
			j = nil
		}
	}()
	keyPath := filepath.Join(dir, "wrapping.key")
	key, readErr := privateRead(keyPath)
	fresh := os.IsNotExist(readErr)
	if os.IsNotExist(readErr) {
		if _, e := os.Stat(filepath.Join(dir, "state.enc")); !os.IsNotExist(e) {
			return j, nil, errJournal
		}
		key = make([]byte, 32)
		rand.Read(key)
		if err = atomicWrite(dir, "wrapping.key", key); err != nil {
			clear(key)
			return j, nil, errJournal
		}
	} else if readErr != nil {
		return j, nil, errJournal
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return j, nil, errJournal
	}
	j.aead, err = cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return j, nil, errJournal
	}
	encrypted, e := privateRead(filepath.Join(dir, "state.enc"))
	if os.IsNotExist(e) {
		if !fresh {
			return j, nil, errJournal
		}
		return j, nil, nil
	}
	if e != nil {
		return j, nil, errJournal
	}
	raw, err = j.aead.Open(nil, nil, encrypted, []byte("transeuroogs-relay-state-v1"))
	if err != nil {
		return j, nil, errJournal
	}
	return j, raw, nil
}

func privateRead(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || s.Size() > 128<<20 {
		return nil, errJournal
	}
	return io.ReadAll(f)
}
func atomicWrite(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return errJournal
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return errJournal
	}
	if err = f.Sync(); err != nil {
		return errJournal
	}
	if err = f.Close(); err != nil {
		return errJournal
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, name)); err != nil {
		return errJournal
	}
	d, err := os.Open(dir)
	if err != nil {
		return errJournal
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return errJournal
	}
	return nil
}
func (j *journal) save(raw []byte) error {
	return atomicWrite(j.dir, "state.enc", j.aead.Seal(nil, nil, raw, []byte("transeuroogs-relay-state-v1")))
}
func (j *journal) close() {
	if j != nil && j.lock != nil {
		_ = syscall.Flock(int(j.lock.Fd()), syscall.LOCK_UN)
		_ = j.lock.Close()
		j.lock = nil
	}
}
