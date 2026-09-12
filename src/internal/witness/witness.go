// Package witness provides a separate monotonic checkpoint authority. It holds
// ciphertext digests and versions only, never key material or key fingerprints.
package witness

import (
	"encoding/hex"
	"encoding/json"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
	"sync"
)

type Fence struct {
	Namespace  string
	Generation string
	Version    int64
	Digest     string
	Witnessed  bool `json:",omitempty"`
}

func (f Fence) Valid() bool {
	b, e := hex.DecodeString(f.Digest)
	return len(f.Namespace) > 0 && len(f.Namespace) <= 128 && core.KeyID(f.Generation).Valid() && f.Version >= 0 && e == nil && len(b) == 32 && f.Witnessed
}

type Authority interface {
	Current(string) (Fence, error)
	Advance(Fence, Fence) error
}
type Local struct {
	mu      sync.Mutex
	store   durable.Store
	records map[string]Fence
	broken  bool
}

func Open(store durable.Store, raw []byte) (*Local, error) {
	if store == nil {
		return nil, core.ErrInvalid
	}
	defer clear(raw)
	l := &Local{store: store, records: map[string]Fence{}}
	if raw != nil {
		if json.Unmarshal(raw, &l.records) != nil || l.records == nil || len(l.records) > 1024 {
			return nil, durable.ErrState
		}
		for ns, f := range l.records {
			if ns != f.Namespace || !f.Valid() {
				return nil, durable.ErrState
			}
		}
	}
	if e := l.save(); e != nil {
		return nil, e
	}
	return l, nil
}
func (l *Local) save() error {
	raw, e := json.Marshal(l.records)
	if e == nil {
		e = l.store.Save(raw)
	}
	if e != nil {
		l.broken = true
		return durable.ErrState
	}
	return nil
}
func (l *Local) Current(ns string) (Fence, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.broken {
		return Fence{}, durable.ErrState
	}
	return l.records[ns], nil
}
func (l *Local) Advance(before, next Fence) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.broken {
		return durable.ErrState
	}
	if !next.Valid() {
		return core.ErrInvalid
	}
	current := l.records[next.Namespace]
	if current == next {
		return nil
	} // exact replay of an uncertain CAS response
	if current != before {
		return durable.ErrState
	}
	if before == (Fence{}) {
		if next.Version != 0 || len(l.records) >= 1024 {
			return core.ErrInvalid
		}
	} else if !before.Valid() || before.Namespace != next.Namespace || before.Generation != next.Generation || next.Version != before.Version+1 {
		return core.ErrInvalid
	}
	l.records[next.Namespace] = next
	return l.save()
}
func (l *Local) Close() { l.mu.Lock(); defer l.mu.Unlock(); l.broken = true; l.store.Close() }
