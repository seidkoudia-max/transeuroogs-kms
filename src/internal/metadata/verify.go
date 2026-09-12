package metadata

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
)

// Trust is an explicit offline issuer allowlist. Revoked credentials fail even
// for old records; finer historical-revocation rules require a partner profile.
type Trust struct {
	Issuer        string             `json:"issuer"`
	Domain        string             `json:"domain"`
	Namespace     string             `json:"namespace"`
	CredentialID  string             `json:"credential_id"`
	PublicKeyFile string             `json:"public_key_file"`
	Pairs         []core.Association `json:"pairs"`
	ValidFrom     time.Time          `json:"valid_from"`
	ValidUntil    time.Time          `json:"valid_until"`
	Revoked       bool               `json:"revoked"`
}

func LoadPublic(path string) (*ecdsa.PublicKey, error) {
	info, e := os.Stat(path)
	if e != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
		return nil, ErrEvidence
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, ErrEvidence
	}
	p, rest := pem.Decode(b)
	if p == nil || p.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrEvidence
	}
	k, e := x509.ParsePKIXPublicKey(p.Bytes)
	if e != nil {
		return nil, ErrEvidence
	}
	key, ok := k.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, ErrEvidence
	}
	return key, nil
}

// VerifyPages authenticates pages and events before cross-node tracing. Exact
// replays are deduplicated; conflicting IDs or adjacent hash links are rejected.
// Missing pages remain partial coverage, never a clean incident conclusion.
func VerifyPages(pages []SignedPage, trust []Trust, audience string) ([]Event, []Coverage, error) {
	if len(pages) == 0 || len(pages) > 10000 || len(trust) == 0 || len(trust) > 64 || !name(audience) {
		return nil, nil, ErrEvidence
	}
	type issuer struct {
		trust  Trust
		public *ecdsa.PublicKey
		first  *Page
		pages  []Page
		events map[uint64]SignedEvent
	}
	issuers := map[string]*issuer{}
	for _, t := range trust {
		if !name(t.Issuer) || !name(t.Domain) || !name(t.Namespace) || !name(t.CredentialID) || len(t.Pairs) == 0 || t.ValidFrom.IsZero() || !t.ValidUntil.After(t.ValidFrom) || issuers[t.Issuer] != nil {
			return nil, nil, ErrEvidence
		}
		for i, a := range t.Pairs {
			if !a.Valid() || slices.Contains(t.Pairs[:i], a) {
				return nil, nil, ErrEvidence
			}
		}
		p, e := LoadPublic(t.PublicKeyFile)
		if e != nil {
			return nil, nil, e
		}
		issuers[t.Issuer] = &issuer{trust: t, public: p, events: map[uint64]SignedEvent{}}
	}
	seenIDs := map[EventRef]SignedEvent{}
	count := 0
	for _, signed := range pages {
		i := issuers[signed.Page.Issuer]
		if i == nil || i.trust.Revoked {
			return nil, nil, ErrEvidence
		}
		var p Page
		if verify(signed.JWS, i.public, i.trust.CredentialID, &p, 256<<10) != nil || !reflect.DeepEqual(p, signed.Page) || p.Profile != Profile || p.Issuer != i.trust.Issuer || p.Domain != i.trust.Domain || p.Namespace != i.trust.Namespace || p.Audience != audience || p.StartedAt.IsZero() || p.ObservedAt.Before(p.StartedAt) || p.ObservedAt.Before(i.trust.ValidFrom) || !p.ObservedAt.Before(i.trust.ValidUntil) || p.After > p.Next || p.Next > p.Watermark || p.Complete != (p.Next == p.Watermark) || len(p.Scope) == 0 || len(p.Events) > MaxPage {
			return nil, nil, ErrEvidence
		}
		for n, a := range p.Scope {
			if !slices.Contains(i.trust.Pairs, a) || slices.Contains(p.Scope[:n], a) {
				return nil, nil, ErrEvidence
			}
		}
		if i.first == nil {
			first := p
			i.first = &first
		} else if p.Watermark != i.first.Watermark || !p.StartedAt.Equal(i.first.StartedAt) || !p.ObservedAt.Equal(i.first.ObservedAt) || !reflect.DeepEqual(p.Scope, i.first.Scope) {
			return nil, nil, ErrEvidence
		}
		i.pages = append(i.pages, p)
		last := p.After
		for _, proof := range p.Events {
			var e Event
			if verify(proof.JWS, i.public, i.trust.CredentialID, &e, 32768) != nil || !reflect.DeepEqual(e, proof.Event) || e.Profile != Profile || e.Issuer != p.Issuer || e.Domain != p.Domain || !e.ID.Valid() || e.Sequence <= last || e.Sequence > p.Next || e.RecordedAt.Before(p.StartedAt) || e.RecordedAt.After(p.ObservedAt) || e.RecordedAt.Before(i.trust.ValidFrom) || !e.RecordedAt.Before(i.trust.ValidUntil) || (e.Record == nil) == (e.Attempt == nil) || len(e.Actions) == 0 {
				return nil, nil, ErrEvidence
			}
			if e.ClockUncertaintyMS != nil && (*e.ClockUncertaintyMS < 0 || *e.ClockUncertaintyMS > 60000) {
				return nil, nil, ErrEvidence
			}
			if !slices.Contains(p.Scope, eventPair(e)) {
				return nil, nil, ErrEvidence
			}
			if e.Record != nil && (e.Record.Key.Namespace != p.Namespace || !e.Record.valid()) {
				return nil, nil, ErrEvidence
			}
			if e.Attempt != nil && (!e.Attempt.valid() || e.PreviousKeyEvent != "" || !slices.Equal(e.Actions, []string{"upstream_" + e.Attempt.Status})) {
				return nil, nil, ErrEvidence
			}
			ref := EventRef{e.Issuer, e.ID}
			if old, ok := seenIDs[ref]; ok && !reflect.DeepEqual(old, proof) {
				return nil, nil, ErrEvidence
			}
			if old, ok := i.events[e.Sequence]; ok && !reflect.DeepEqual(old, proof) {
				return nil, nil, ErrEvidence
			}
			if _, ok := seenIDs[ref]; !ok {
				count++
				if count > 100000 {
					return nil, nil, ErrEvidence
				}
			}
			seenIDs[ref] = proof
			i.events[e.Sequence] = proof
			last = e.Sequence
		}
	}
	events := []Event{}
	coverage := []Coverage{}
	names := []string{}
	for id, i := range issuers {
		if i.first != nil {
			names = append(names, id)
		}
	}
	sort.Strings(names)
	for _, id := range names {
		i := issuers[id]
		sort.Slice(i.pages, func(a, b int) bool { return i.pages[a].After < i.pages[b].After })
		covered := uint64(0)
		for _, p := range i.pages {
			if p.After <= covered {
				covered = max(covered, p.Next)
			}
		}
		complete := covered == i.first.Watermark
		seq := []uint64{}
		for n := range i.events {
			seq = append(seq, n)
		}
		sort.Slice(seq, func(a, b int) bool { return seq[a] < seq[b] })
		lastKey := map[KeyRef]core.KeyID{}
		lastRecord := map[KeyRef]Record{}
		lastTime := i.first.StartedAt
		for _, n := range seq {
			proof := i.events[n]
			e := proof.Event
			if e.RecordedAt.Before(lastTime) {
				return nil, nil, ErrEvidence
			}
			lastTime = e.RecordedAt
			if n == 1 && e.PreviousDigest != "" {
				return nil, nil, ErrEvidence
			}
			if prev, ok := i.events[n-1]; ok && e.PreviousDigest != checksum([]byte(prev.JWS)) {
				return nil, nil, ErrEvidence
			}
			if e.Record != nil {
				if e.PreviousKeyEvent != lastKey[e.Record.Key] {
					complete = false
				} else {
					before, exists := lastRecord[e.Record.Key]
					if !slices.Equal(e.Actions, actions(before, *e.Record, exists)) {
						return nil, nil, ErrEvidence
					}
				}
				lastKey[e.Record.Key] = e.ID
				lastRecord[e.Record.Key] = *e.Record
			}
			events = append(events, e)
		}
		p := i.first
		coverage = append(coverage, Coverage{Issuer: id, Namespace: p.Namespace, Scope: slices.Clone(p.Scope), StartedAt: p.StartedAt, ObservedAt: p.ObservedAt, Watermark: p.Watermark, Complete: complete, ProviderHistory: "unknown"})
	}
	return events, coverage, nil
}
