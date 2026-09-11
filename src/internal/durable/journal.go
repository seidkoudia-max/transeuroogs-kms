// Package durable provides encrypted, single-writer laboratory snapshots.
package durable

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

type Journal struct {
	context string
	dir     string
	lock    *os.File
	aead    cipher.AEAD
}

var ErrState = errors.New("durable key state unavailable; recovery required")

func Open(dir, context string) (j *Journal, raw []byte, err error) {
	if context == "" {
		return nil, nil, ErrState
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, ErrState
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, nil, ErrState
	}
	lock, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, nil, ErrState
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		lock.Close()
		return nil, nil, ErrState
	}
	j = &Journal{dir: dir, lock: lock, context: context}
	defer func() {
		if err != nil {
			j.Close()
			j = nil
		}
	}()
	keyPath := filepath.Join(dir, "wrapping.key")
	key, readErr := privateRead(keyPath)
	fresh := os.IsNotExist(readErr)
	if os.IsNotExist(readErr) {
		if _, e := os.Stat(filepath.Join(dir, "state.enc")); !os.IsNotExist(e) {
			return j, nil, ErrState
		}
		key = make([]byte, 32)
		rand.Read(key)
		if err = atomicWrite(dir, "wrapping.key", key); err != nil {
			clear(key)
			return j, nil, ErrState
		}
	} else if readErr != nil {
		return j, nil, ErrState
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return j, nil, ErrState
	}
	j.aead, err = cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return j, nil, ErrState
	}
	encrypted, e := privateRead(filepath.Join(dir, "state.enc"))
	if os.IsNotExist(e) {
		if !fresh {
			return j, nil, ErrState
		}
		return j, nil, nil
	}
	if e != nil {
		return j, nil, ErrState
	}
	raw, err = j.aead.Open(nil, nil, encrypted, []byte(j.context))
	if err != nil {
		return j, nil, ErrState
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
		return nil, ErrState
	}
	return io.ReadAll(f)
}
func atomicWrite(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return ErrState
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return ErrState
	}
	if err = f.Sync(); err != nil {
		return ErrState
	}
	if err = f.Close(); err != nil {
		return ErrState
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, name)); err != nil {
		return ErrState
	}
	d, err := os.Open(dir)
	if err != nil {
		return ErrState
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return ErrState
	}
	return nil
}
func (j *Journal) Save(raw []byte) error {
	if j == nil || j.lock == nil {
		return ErrState
	}
	return atomicWrite(j.dir, "state.enc", j.aead.Seal(nil, nil, raw, []byte(j.context)))
}
func (j *Journal) Close() {
	if j != nil && j.lock != nil {
		_ = syscall.Flock(int(j.lock.Fd()), syscall.LOCK_UN)
		_ = j.lock.Close()
		j.lock = nil
	}
}
