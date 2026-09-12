// Package qkdrelay protects terrestrial trusted-relay transfers with one
// independently consumed QKD link key per transfer. The opt-in project profile
// uses RFC 7516 JWE (dir/A256GCM); it does not implement the EAGLE-1 middle segment.
package qkdrelay

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/etsi020"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/peering"
)

const Profile = "transeuroogs-qkd-jwe-v1"
const contentType = "transeuroogs-relay+jwe"
const LifetimeExtension = "E0_transeuroogs_expires_at"

type Provider interface {
	Allocate(int) ([]core.Delivery, error)
	Retrieve([]core.KeyID) ([]core.Delivery, error)
}
type Frame struct {
	JWE string `json:"jwe"`
}

func (Frame) String() string     { return "QKDRelayFrame{ciphertext=[REDACTED]}" }
func (f Frame) GoString() string { return f.String() }

type payload struct {
	Profile  string           `json:"profile"`
	Sender   string           `json:"sender"`
	Receiver string           `json:"receiver"`
	Transfer etsi020.Transfer `json:"transfer"`
}
type entry struct {
	Peer    string
	Digest  string
	Status  string
	LinkID  core.KeyID
	Frame   Frame
	Pending []byte `json:",omitempty"`
}
type state struct {
	Version  int
	Binding  string
	Outbound map[core.KeyID]*entry
	Inbound  map[core.KeyID]*entry
	Used     map[core.KeyID]bool
}
type Bridge struct {
	mu        sync.Mutex
	cfg       peering.Config
	providers map[string]Provider
	store     durable.Store
	s         state
	capacity  int
	broken    bool
	now       func() time.Time
}

func Open(cfg peering.Config, providers map[string]Provider, capacity int, store durable.Store, raw []byte) (*Bridge, error) {
	defer clear(raw)
	if cfg.Validate() != nil || capacity < 1 || capacity > 100000 || store == nil {
		return nil, core.ErrInvalid
	}
	bound, _ := json.Marshal(struct {
		Config   peering.Config
		Capacity int
	}{cfg, capacity})
	h := sha256.Sum256(bound)
	var owned peering.Config
	copyConfig, _ := json.Marshal(cfg)
	_ = json.Unmarshal(copyConfig, &owned)
	b := &Bridge{cfg: owned, providers: providers, capacity: capacity, store: store, now: time.Now, s: state{Version: 1, Binding: hex.EncodeToString(h[:]), Outbound: map[core.KeyID]*entry{}, Inbound: map[core.KeyID]*entry{}, Used: map[core.KeyID]bool{}}}
	for id, p := range cfg.Peers {
		if p.Mode == peering.QKDRelay && (providers[id] == nil || p.Link == nil) {
			return nil, core.ErrInvalid
		}
	}
	if raw != nil {
		binding := b.s.Binding
		if json.Unmarshal(raw, &b.s) != nil || b.s.Version != 1 || b.s.Binding != binding || b.s.Inbound == nil || b.s.Outbound == nil || b.s.Used == nil || len(b.s.Inbound)+len(b.s.Outbound) > capacity {
			return nil, durable.ErrState
		}
		for _, entries := range []map[core.KeyID]*entry{b.s.Outbound, b.s.Inbound} {
			for id, e := range entries {
				if !id.Valid() || e == nil || cfg.Peers[e.Peer].Mode != peering.QKDRelay {
					return nil, durable.ErrState
				}
				if e.Status == "collecting" {
					e.Status = "uncertain"
					clear(e.Pending)
					e.Pending = nil
				}
			}
		}
	}
	if e := b.save(); e != nil {
		return nil, e
	}
	return b, nil
}
func (b *Bridge) save() error {
	if b.broken {
		return durable.ErrState
	}
	raw, e := json.Marshal(b.s)
	defer clear(raw)
	if e == nil {
		e = b.store.Save(raw)
	}
	if e != nil {
		b.broken = true
		return durable.ErrState
	}
	return nil
}
func (b *Bridge) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.broken = true
	for _, e := range b.s.Inbound {
		clear(e.Pending)
		e.Pending = nil
	}
	b.store.Close()
}
func checksum(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func wipe(d []core.Delivery) {
	for _, k := range d {
		clear(k.Material)
	}
}

// Seal commits its intent before consuming a link key. Retries return the exact
// cached ciphertext; neither a retry nor a different peer may consume a new key.
func (b *Bridge) Seal(peer string, t etsi020.Transfer) (Frame, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.cfg.Peers[peer]
	if b.broken {
		return Frame{}, durable.ErrState
	}
	if !ok || p.Mode != peering.QKDRelay || p.Link.Role != "master" {
		return Frame{}, core.ErrUnauthorized
	}
	if t.Validate() != nil || len(t.Keys) != 1 || !validLifetime(t, b.now()) {
		return Frame{}, core.ErrInvalid
	}
	id := t.Keys[0].ID
	raw, e := json.Marshal(payload{Profile, b.cfg.Identity, p.Identity, t})
	defer clear(raw)
	if e != nil {
		return Frame{}, e
	}
	digest := checksum(raw)
	if old := b.s.Outbound[id]; old != nil {
		if old.Peer != peer || old.Digest != digest {
			return Frame{}, core.ErrDuplicate
		}
		if old.Status != "sealed" {
			return Frame{}, core.ErrUnavailable
		}
		return old.Frame, nil
	}
	if len(b.s.Outbound)+len(b.s.Inbound) >= b.capacity {
		return Frame{}, core.ErrCapacity
	}
	ent := &entry{Peer: peer, Digest: digest, Status: "collecting"}
	b.s.Outbound[id] = ent
	if e = b.save(); e != nil {
		return Frame{}, e
	}
	keys, e := b.providers[peer].Allocate(1)
	defer wipe(keys)
	valid := e == nil && len(keys) == 1 && keys[0].ID.Valid() && keys[0].ID != id && len(keys[0].Material) == 32 && !b.s.Used[keys[0].ID]
	// Even a failed or malformed consuming reply can expose known IDs. Retain
	// their tombstones so a later provider response cannot recycle them.
	for _, key := range keys {
		if key.ID.Valid() {
			b.s.Used[key.ID] = true
		}
	}
	if !valid {
		ent.Status = "uncertain"
		_ = b.save()
		return Frame{}, core.ErrUnavailable
	}
	ent.LinkID = keys[0].ID
	encrypter, e := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: keys[0].Material, KeyID: string(ent.LinkID)}, (&jose.EncrypterOptions{}).WithType(contentType))
	if e != nil {
		ent.Status = "uncertain"
		_ = b.save()
		return Frame{}, core.ErrUnavailable
	}
	obj, e := encrypter.Encrypt(raw)
	if e != nil {
		ent.Status = "uncertain"
		_ = b.save()
		return Frame{}, core.ErrUnavailable
	}
	ent.Frame.JWE, e = obj.CompactSerialize()
	if e != nil {
		ent.Status = "uncertain"
		_ = b.save()
		return Frame{}, core.ErrUnavailable
	}
	ent.Status = "sealed"
	if e = b.save(); e != nil {
		return Frame{}, e
	}
	return ent.Frame, nil
}

func parse(frame Frame) (core.KeyID, *jose.JSONWebEncryption, error) {
	if len(frame.JWE) > 32768 || strings.Count(frame.JWE, ".") != 4 {
		return "", nil, core.ErrInvalid
	}
	head, _, _ := strings.Cut(frame.JWE, ".")
	raw, e := base64.RawURLEncoding.DecodeString(head)
	var h struct {
		Alg  string     `json:"alg"`
		Enc  string     `json:"enc"`
		Key  core.KeyID `json:"kid"`
		Type string     `json:"typ"`
	}
	if e != nil || json.Unmarshal(raw, &h) != nil || h.Alg != "dir" || h.Enc != "A256GCM" || !h.Key.Valid() || h.Type != contentType {
		return "", nil, core.ErrInvalid
	}
	want, _ := json.Marshal(h)
	if !bytes.Equal(raw, want) {
		return "", nil, core.ErrInvalid
	}
	obj, e := jose.ParseEncryptedCompact(frame.JWE, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A256GCM})
	return h.Key, obj, e
}
func validLifetime(t etsi020.Transfer, now time.Time) bool {
	if len(t.Keys) != 1 {
		return false
	}
	var expiry time.Time
	return json.Unmarshal(t.Keys[0].Extension[LifetimeExtension], &expiry) == nil && now.Before(expiry) && expiry.Sub(now) <= 24*time.Hour
}

// Accept journals link-key consumption and the decrypted pending handoff. A
// failure after decryption can retry the same engine handoff without fetching a
// link key again. An interrupted consuming retrieval remains burned/uncertain.
func (b *Bridge) Accept(peer string, frame Frame, accept func(string, etsi020.Transfer) error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.cfg.Peers[peer]
	if b.broken {
		return durable.ErrState
	}
	if !ok || p.Mode != peering.QKDRelay || !p.Incoming || p.Link.Role != "slave" {
		return core.ErrUnauthorized
	}
	id, obj, e := parse(frame)
	if e != nil {
		return core.ErrInvalid
	}
	digest := checksum([]byte(frame.JWE))
	ent := b.s.Inbound[id]
	if ent != nil {
		if ent.Peer != peer || ent.Digest != digest {
			return core.ErrDuplicate
		}
		if ent.Status == "accepted" {
			return nil
		}
		if ent.Status != "decrypted" {
			return core.ErrUnavailable
		}
	} else {
		if b.s.Used[id] {
			return core.ErrDuplicate
		}
		if len(b.s.Inbound)+len(b.s.Outbound) >= b.capacity {
			return core.ErrCapacity
		}
		ent = &entry{Peer: peer, Digest: digest, LinkID: id, Status: "collecting"}
		b.s.Inbound[id] = ent
		b.s.Used[id] = true
		if e = b.save(); e != nil {
			return e
		}
		keys, e := b.providers[peer].Retrieve([]core.KeyID{id})
		defer wipe(keys)
		if e != nil || len(keys) != 1 || keys[0].ID != id || len(keys[0].Material) != 32 {
			ent.Status = "uncertain"
			_ = b.save()
			return core.ErrUnavailable
		}
		ent.Pending, e = obj.Decrypt(keys[0].Material)
		if e != nil || len(ent.Pending) > 16384 {
			clear(ent.Pending)
			ent.Pending = nil
			ent.Status = "uncertain"
			_ = b.save()
			return core.ErrUnavailable
		}
		ent.Status = "decrypted"
		if e = b.save(); e != nil {
			return e
		}
	}
	reject := func() error {
		clear(ent.Pending)
		ent.Pending = nil
		ent.Status = "uncertain"
		if e := b.save(); e != nil {
			return e
		}
		return core.ErrInvalid
	}
	var v payload
	if json.Unmarshal(ent.Pending, &v) != nil || v.Profile != Profile || v.Sender != p.Identity || v.Receiver != b.cfg.Identity || v.Transfer.Validate() != nil || !validLifetime(v.Transfer, b.now()) || v.Transfer.Keys[0].ID == id {
		return reject()
	}
	want, _ := json.Marshal(v)
	defer clear(want)
	if !bytes.Equal(want, ent.Pending) {
		return reject()
	}
	if e = accept(peer, v.Transfer); e != nil {
		return e
	}
	clear(ent.Pending)
	ent.Pending = nil
	ent.Status = "accepted"
	return b.save()
}
