package metadata

import (
	"encoding/json"
	"reflect"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
)

type history struct {
	Profile  string            `json:"profile"`
	Binding  string            `json:"binding"`
	Started  time.Time         `json:"started_at"`
	Observed time.Time         `json:"observed_at"`
	Aliases  map[string]string `json:"private_attempt_aliases"`
	Events   []SignedEvent     `json:"events"`
}

// Store adds history to the SAME encrypted lifecycle snapshot. Its underlying
// commit is the only durability boundary; there is no second database write.
type Store struct {
	mu      sync.Mutex
	cfg     Config
	inner   durable.Store
	project Projector
	signing *Signing
	now     func() time.Time
	h       history
	last    Projection
	lastKey map[core.KeyID]core.KeyID
	broken  bool
	closed  bool
}

func Open(c Config, signing *Signing, inner durable.Store, raw []byte, project Projector, clock func() time.Time) (*Store, []byte, error) {
	defer clear(raw)
	if c.Validate() != nil || signing == nil || inner == nil || project == nil || signing.kid != c.CredentialID {
		return nil, nil, core.ErrInvalid
	}
	if clock == nil {
		clock = time.Now
	}
	binding, _ := marshal(struct {
		Profile, Domain, Issuer, Namespace, Credential, Public string
		Limit                                                  int
		Clock                                                  *int64
	}{Profile, c.Domain, c.Issuer, c.Namespace, c.CredentialID, signing.fingerprint, c.MaxEvents, c.ClockUncertaintyMS})
	s := &Store{cfg: clone(c), inner: inner, signing: signing, project: project, now: clock, lastKey: map[core.KeyID]core.KeyID{}}
	s.h = history{Profile: Profile, Binding: checksum(binding), Started: clock().UTC(), Observed: clock().UTC(), Aliases: map[string]string{}, Events: []SignedEvent{}}
	s.last = Projection{Keys: map[core.KeyID]Record{}, Attempts: map[string]Attempt{}}
	if raw == nil {
		return s, nil, nil
	}
	if len(raw) > MaxSnapshotBytes {
		return nil, nil, durable.ErrState
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object[SnapshotField] == nil {
		return nil, nil, durable.ErrState
	}
	defer func() {
		for _, v := range object {
			clear(v)
		}
	}()
	var recovered history
	if decode(object[SnapshotField], &recovered) != nil || recovered.Profile != Profile || recovered.Binding != s.h.Binding || recovered.Started.IsZero() || recovered.Observed.Before(recovered.Started) || recovered.Observed.After(clock()) || recovered.Aliases == nil || recovered.Events == nil || len(recovered.Events) > c.MaxEvents {
		return nil, nil, durable.ErrState
	}
	delete(object, SnapshotField)
	clean, e := json.Marshal(object)
	if e != nil {
		return nil, nil, durable.ErrState
	}
	p, e := project(clean)
	if e != nil || s.normalize(&p) != nil {
		clear(clean)
		return nil, nil, durable.ErrState
	}
	keys := map[core.KeyID]Record{}
	controls := []allocation.Commit{}
	attempts := map[string]AttemptView{}
	seen := map[core.KeyID]bool{}
	previous := ""
	when := recovered.Started
	for i, proof := range recovered.Events {
		var event Event
		if verify(proof.JWS, signing.public, signing.kid, &event, 32768) != nil || !reflect.DeepEqual(event, proof.Event) || event.Profile != Profile || event.Issuer != c.Issuer || event.Domain != c.Domain || event.Sequence != uint64(i+1) || event.PreviousDigest != previous || !event.ID.Valid() || seen[event.ID] || event.RecordedAt.Before(when) || event.RecordedAt.After(recovered.Observed) || !reflect.DeepEqual(event.ClockUncertaintyMS, c.ClockUncertaintyMS) {
			clear(clean)
			return nil, nil, durable.ErrState
		}
		seen[event.ID] = true
		when = event.RecordedAt
		previous = checksum([]byte(proof.JWS))
		if !event.onePayload() {
			clear(clean)
			return nil, nil, durable.ErrState
		}
		if event.Record != nil {
			r := *event.Record
			before, exists := keys[r.Key.ID]
			if !r.valid() || r.Key.Namespace != c.Namespace || event.PreviousKeyEvent != s.lastKey[r.Key.ID] || !slices.Equal(event.Actions, actions(before, r, exists)) {
				clear(clean)
				return nil, nil, durable.ErrState
			}
			keys[r.Key.ID] = r
			s.lastKey[r.Key.ID] = event.ID
		} else if event.Attempt != nil {
			if !event.Attempt.valid() || event.PreviousKeyEvent != "" || !slices.Equal(event.Actions, []string{"upstream_" + event.Attempt.Status}) {
				clear(clean)
				return nil, nil, durable.ErrState
			}
			attempts[event.Attempt.Reference] = *event.Attempt
		} else if event.Control != nil {
			if !event.Control.Valid() || event.Control.Revision != uint64(len(controls)+1) || event.Control.AppliedAt.After(event.RecordedAt) || event.PreviousKeyEvent != "" || !slices.Equal(event.Actions, []string{"allocation_changed"}) {
				clear(clean)
				return nil, nil, durable.ErrState
			}
			controls = append(controls, *event.Control)
		} else {
			clear(clean)
			return nil, nil, durable.ErrState
		}
	}
	if !reflect.DeepEqual(controls, p.Controls) || !reflect.DeepEqual(keys, p.Keys) || len(recovered.Aliases) != len(p.Attempts) || len(attempts) != len(p.Attempts) {
		clear(clean)
		return nil, nil, durable.ErrState
	}
	for id, a := range p.Attempts {
		alias := recovered.Aliases[id]
		if alias == "" || !reflect.DeepEqual(attempts[alias], attemptView(a, alias)) {
			clear(clean)
			return nil, nil, durable.ErrState
		}
	}
	s.h, s.last = recovered, p
	return s, clean, nil
}

func (s *Store) normalize(p *Projection) error {
	if p.Controls == nil {
		p.Controls = []allocation.Commit{}
	}
	for i, c := range p.Controls {
		if !c.Valid() || c.Revision != uint64(i+1) {
			return ErrEvidence
		}
	}
	if p.Keys == nil {
		return ErrEvidence
	}
	if p.Attempts == nil {
		p.Attempts = map[string]Attempt{}
	}
	for id, r := range p.Keys {
		r.Key.Namespace = s.cfg.Namespace
		if r.Key.ID != id || !r.valid() {
			return ErrEvidence
		}
		p.Keys[id] = r
	}
	for id, a := range p.Attempts {
		if id == "" || id != a.ID || !attemptView(a, "").validFields() {
			return ErrEvidence
		}
	}
	return nil
}

func actions(before, after Record, exists bool) []string {
	a := []string{}
	if !exists {
		a = append(a, "key_observed")
	}
	if after.HoldingMaterial && (!exists || !before.HoldingMaterial) {
		a = append(a, "custody_started")
	}
	if exists && before.HoldingMaterial && !after.HoldingMaterial {
		a = append(a, "material_cleared")
	}
	if after.MasterState != "" && (!exists || before.MasterState != after.MasterState) {
		a = append(a, "master_"+string(after.MasterState))
	}
	if after.SlaveState != "" && (!exists || before.SlaveState != after.SlaveState) {
		a = append(a, "slave_"+string(after.SlaveState))
	}
	if after.TransferIntent && (!exists || !before.TransferIntent) {
		a = append(a, "transfer_intent")
	}
	if after.Ready && (!exists || !before.Ready) {
		a = append(a, "delivery_ready")
	}
	if after.Voiding && (!exists || !before.Voiding) {
		a = append(a, "void_started")
	}
	if after.Uncertain && (!exists || !before.Uncertain) {
		a = append(a, "outcome_uncertain")
	}
	if len(a) == 0 {
		a = append(a, "state_observed")
	}
	return a
}

func attemptView(a Attempt, alias string) AttemptView {
	return AttemptView{alias, a.Association, slices.Clone(a.IDs), a.Count, a.Status, a.Started}
}

func (s *Store) Save(raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken || s.closed {
		return durable.ErrState
	}
	// Fail closed after EVERY unsuccessful save, including capacity/signing errors.
	ok := false
	defer func() {
		if !ok {
			s.broken = true
		}
	}()
	if len(raw) > MaxSnapshotBytes {
		return durable.ErrState
	}
	p, e := s.project(raw)
	if e != nil || s.normalize(&p) != nil {
		return durable.ErrState
	}
	now := s.now().UTC()
	if now.Before(s.h.Observed) {
		return durable.ErrState
	}
	next := s.h
	next.Observed = now
	next.Events = append([]SignedEvent{}, s.h.Events...)
	next.Aliases = map[string]string{}
	for id, alias := range s.h.Aliases {
		next.Aliases[id] = alias
	}
	lastKey := map[core.KeyID]core.KeyID{}
	for id, event := range s.lastKey {
		lastKey[id] = event
	}
	appendEvent := func(event Event) error {
		if len(next.Events) >= s.cfg.MaxEvents {
			return durable.ErrState
		}
		event.Profile, event.ID, event.Domain, event.Issuer = Profile, core.NewID(), s.cfg.Domain, s.cfg.Issuer
		event.Sequence, event.RecordedAt, event.ClockUncertaintyMS = uint64(len(next.Events)+1), now, s.cfg.ClockUncertaintyMS
		if len(next.Events) > 0 {
			event.PreviousDigest = checksum([]byte(next.Events[len(next.Events)-1].JWS))
		}
		if event.Record != nil {
			event.PreviousKeyEvent = lastKey[event.Record.Key.ID]
			lastKey[event.Record.Key.ID] = event.ID
		}
		token, e := s.signing.Sign(event)
		if e != nil {
			return e
		}
		next.Events = append(next.Events, SignedEvent{event, token})
		return nil
	}
	if len(p.Controls) < len(s.last.Controls) {
		return durable.ErrState
	}
	for i, c := range p.Controls {
		if i < len(s.last.Controls) {
			if !reflect.DeepEqual(c, s.last.Controls[i]) {
				return durable.ErrState
			}
		} else {
			if c.AppliedAt.After(now) {
				return durable.ErrState
			}
			if e := appendEvent(Event{Actions: []string{"allocation_changed"}, Control: &c}); e != nil {
				return e
			}
		}
	}
	// Deterministic ordering makes batches reproducible without relying on Go maps.
	ids := make([]string, 0, len(p.Keys))
	for id := range p.Keys {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := p.Keys[core.KeyID(id)]
		before, exists := s.last.Keys[r.Key.ID]
		if exists && before.Key != r.Key {
			return durable.ErrState
		}
		if !exists || !reflect.DeepEqual(before, r) {
			if e := appendEvent(Event{Actions: actions(before, r, exists), Record: &r}); e != nil {
				return e
			}
		}
	}
	for id := range s.last.Keys {
		if _, ok := p.Keys[id]; !ok {
			return durable.ErrState
		}
	}
	ids = ids[:0]
	for id := range p.Attempts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		a := p.Attempts[id]
		before, exists := s.last.Attempts[id]
		if !exists {
			next.Aliases[id] = string(core.NewID())
		}
		if !exists || !reflect.DeepEqual(before, a) {
			v := attemptView(a, next.Aliases[id])
			if e := appendEvent(Event{Actions: []string{"upstream_" + a.Status}, Attempt: &v}); e != nil {
				return e
			}
		}
	}
	for id := range s.last.Attempts {
		if _, ok := p.Attempts[id]; !ok {
			return durable.ErrState
		}
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object[SnapshotField] != nil {
		return durable.ErrState
	}
	defer func() {
		for _, v := range object {
			clear(v)
		}
	}()
	object[SnapshotField], e = marshal(next)
	if e != nil {
		return durable.ErrState
	}
	b, e := json.Marshal(object)
	defer clear(b)
	if e != nil || len(b) > MaxSnapshotBytes || s.inner.Save(b) != nil {
		return durable.ErrState
	}
	s.h, s.last, s.lastKey = next, p, lastKey
	ok = true
	return nil
}

func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.inner.Close()
	}
}

func eventPair(e Event) core.Association {
	if e.Record != nil {
		return e.Record.Key.Association
	}
	if e.Attempt != nil {
		return e.Attempt.Association
	}
	if e.Control != nil {
		return e.Control.Command.Association
	}
	return core.Association{}
}

func (s *Store) Key(id core.KeyID, audience, sae string, pairs []core.Association) (SignedKeyView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken || s.closed {
		return SignedKeyView{}, durable.ErrState
	}
	r, ok := s.last.Keys[id]
	if !ok || !slices.Contains(pairs, r.Key.Association) {
		return SignedKeyView{}, core.ErrUnavailable
	}
	v := KeyView{Profile: Profile, Issuer: s.cfg.Issuer, Audience: audience, Key: r.Key, SourceClass: r.SourceClass, SourceEvidence: r.SourceEvidence, GenerationTime: r.GenerationTime, LocalExpiresAt: r.LocalExpiresAt, RecordedAt: s.h.Observed, HistoryStarted: s.h.Started, EvidenceScope: "local_observation; provider_history_unknown"}
	if sae == r.Key.Association.Master {
		v.State = r.MasterState
	}
	if sae == r.Key.Association.Slave {
		v.State = r.SlaveState
	}
	// This is a committed-state observation, not a live delivery authorization.
	token, e := s.signing.Sign(v)
	return clone(SignedKeyView{v, token}), e
}

func (s *Store) Page(audience string, pairs []core.Association, after, through uint64, limit int) (SignedPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken || s.closed {
		return SignedPage{}, durable.ErrState
	}
	if through == 0 {
		through = uint64(len(s.h.Events))
	}
	if limit < 1 || limit > MaxPage || after > through || through > uint64(len(s.h.Events)) {
		return SignedPage{}, core.ErrInvalid
	}
	p := Page{Profile: Profile, Domain: s.cfg.Domain, Issuer: s.cfg.Issuer, Namespace: s.cfg.Namespace, Audience: audience, StartedAt: s.h.Started, ObservedAt: s.h.Observed, Watermark: through, After: after, Next: after, Scope: slices.Clone(pairs), Events: []SignedEvent{}}
	for p.Next < through && len(p.Events) < limit {
		e := s.h.Events[p.Next]
		if slices.Contains(pairs, eventPair(e.Event)) {
			p.Events = append(p.Events, e)
			b, _ := marshal(p)
			if len(b) > 48<<10 {
				p.Events = p.Events[:len(p.Events)-1]
				if len(p.Events) == 0 {
					return SignedPage{}, core.ErrCapacity
				}
				break
			}
		}
		p.Next++
	}
	// A fixed watermark has a fixed time boundary even if more events arrive
	// between page requests. Later unrecorded custody remains outside coverage.
	if through > 0 {
		p.ObservedAt = s.h.Events[through-1].Event.RecordedAt
	} else {
		p.ObservedAt = p.StartedAt
	}
	p.Complete = p.Next == through
	token, e := s.signing.Sign(p)
	return clone(SignedPage{p, token}), e
}

func (s *Store) Trace(q Query, pairs []core.Association) (Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken || s.closed {
		return Report{}, durable.ErrState
	}
	events := []Event{}
	for _, e := range s.h.Events {
		if slices.Contains(pairs, eventPair(e.Event)) {
			events = append(events, e.Event)
		}
	}
	return Trace(q, events, []Coverage{{Issuer: s.cfg.Issuer, Namespace: s.cfg.Namespace, Scope: slices.Clone(pairs), StartedAt: s.h.Started, ObservedAt: s.h.Observed, Watermark: uint64(len(s.h.Events)), Complete: true, ProviderHistory: "unknown"}})
}
