package relay

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sync"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/etsi020"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/peering"
)

type record struct {
	ID           core.KeyID
	Pair         core.Association
	Role         string
	Material     []byte
	Digest       string
	KeyExtension etsi020.Extension
	Optional     etsi020.Extension
	Sender       string
	Next         string
	Candidates   []string
	Sent         bool
	Ready        bool
	Delivered    bool
	Token        core.KeyID
	Created      time.Time
	Expires      time.Time
	Voiding      bool
	VoidFailed   bool
	VoidPending  map[string]bool
	VoidRequests map[string]bool
	Unknown      bool
	Retry        time.Time
}
type ackJob struct {
	Peer  string
	Ack   etsi020.Ack
	Retry time.Time
}

func (j ackJob) keyID() core.KeyID {
	if len(j.Ack.IDs) == 0 {
		return ""
	}
	return j.Ack.IDs[0].ID
}

type state struct {
	Version int
	Binding string
	Keys    map[core.KeyID]*record
	Order   []core.KeyID
	Cursor  map[string]int
	Acks    map[core.KeyID]ackJob
}
type Engine struct {
	mu        sync.Mutex
	step      sync.Mutex
	cfg       peering.Config
	allowed   map[core.Association]bool
	capacity  int
	s         state
	j         *journal
	broken    bool
	transport etsi020.Transport
	now       func() time.Time
	retry     time.Duration
}

func Open(cfg peering.Config, associations []core.Association, capacity int, tr etsi020.Transport) (*Engine, error) {
	j, raw, err := openJournal(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	return OpenStore(cfg, associations, capacity, tr, j.Store, raw)
}

func OpenStore(cfg peering.Config, associations []core.Association, capacity int, tr etsi020.Transport, store durable.Store, raw []byte) (*Engine, error) {
	defer clear(raw)
	success := false
	defer func() {
		if !success && store != nil {
			store.Close()
		}
	}()
	if cfg.Validate() != nil || capacity < 1 || capacity > 100000 || tr == nil || store == nil {
		return nil, core.ErrInvalid
	}
	// Own configuration and extension buffers; callers cannot change active policy.
	buf, _ := json.Marshal(cfg)
	var owned peering.Config
	_ = json.Unmarshal(buf, &owned)
	bindingBytes, _ := json.Marshal(struct {
		Config       peering.Config
		Associations []core.Association
		Capacity     int
	}{cfg, associations, capacity})
	hash := sha256.Sum256(bindingBytes)
	binding := hex.EncodeToString(hash[:])
	e := &Engine{cfg: owned, capacity: capacity, transport: tr, allowed: map[core.Association]bool{}, now: time.Now, retry: time.Second}
	for _, a := range associations {
		if !a.Valid() {
			return nil, core.ErrInvalid
		}
		e.allowed[a] = true
	}
	j := &journal{store}
	e.j = j
	var err error
	e.s = state{Version: 1, Binding: binding, Keys: map[core.KeyID]*record{}, Cursor: map[string]int{}, Acks: map[core.KeyID]ackJob{}}
	if raw != nil {
		if json.Unmarshal(raw, &e.s) != nil || e.s.Version != 1 || e.s.Binding != binding || e.s.Keys == nil || e.s.Acks == nil || e.s.Cursor == nil {
			j.close()
			return nil, errJournal
		}
	}
	if err = e.change(func(*state) error { return nil }); err != nil {
		j.close()
		return nil, err
	}
	success = true
	return e, nil
}
func (e *Engine) Close() {
	e.step.Lock()
	defer e.step.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.broken = true
	for _, r := range e.s.Keys {
		clear(r.Material)
	}
	e.j.close()
}

// Every visible transition, outbound transfer intent and recipient consumption
// commits before its side effect. Uncertain disk errors poison this process.
func (e *Engine) change(fn func(*state) error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.broken {
		return errJournal
	}
	raw, err := json.Marshal(e.s)
	if err != nil {
		return errJournal
	}
	defer clear(raw)
	var next state
	if json.Unmarshal(raw, &next) != nil {
		return errJournal
	}
	defer func() {
		for _, r := range next.Keys {
			clear(r.Material)
		}
	}()
	if err = fn(&next); err != nil {
		return err
	}
	encoded, err := json.Marshal(next)
	if err != nil {
		return errJournal
	}
	defer clear(encoded)
	if err = e.j.save(encoded); err != nil {
		e.broken = true
		return errJournal
	}
	for _, r := range e.s.Keys {
		clear(r.Material)
	}
	e.s = next
	next.Keys = nil
	return nil
}
func (e *Engine) local(sae string) bool { return slices.Contains(e.cfg.LocalSAEs, sae) }
func (e *Engine) candidates(s *state, target, sender string) []string {
	route := e.cfg.Routes[target]
	if len(route) == 0 {
		return nil
	}
	start := s.Cursor[target] % len(route)
	s.Cursor[target] = (start + 1) % len(route)
	var out []string
	for i := range route {
		p := route[(start+i)%len(route)]
		if p != sender {
			out = append(out, p)
		}
	}
	return out
}
func digest(k etsi020.Key, a core.Association, opt etsi020.Extension) string {
	b, _ := json.Marshal(struct {
		Key      etsi020.Key
		Pair     core.Association
		Optional etsi020.Extension
	}{k, a, opt})
	defer clear(b)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func cloneExtension(x etsi020.Extension) etsi020.Extension {
	if x == nil {
		return nil
	}
	out := make(etsi020.Extension, len(x))
	for k, v := range x {
		out[k] = slices.Clone(v)
	}
	return out
}
func (e *Engine) StoreKey(k core.Key) error {
	if err := k.Validate(e.now()); err != nil {
		return err
	}
	if !e.allowed[k.Association] || !e.local(k.Association.Master) || e.local(k.Association.Slave) {
		return core.ErrUnauthorized
	}
	return e.change(func(s *state) error {
		if _, ok := s.Keys[k.ID]; ok {
			return core.ErrDuplicate
		}
		if len(s.Keys) >= e.capacity {
			return core.ErrCapacity
		}
		candidates := e.candidates(s, k.Association.Slave, "")
		if len(candidates) == 0 {
			return core.ErrUnavailable
		}
		r := &record{ID: k.ID, Pair: k.Association, Role: "source", Material: slices.Clone(k.Material), Created: k.CreatedAt, Expires: k.ExpiresAt, Candidates: candidates}
		r.Digest = digest(etsi020.Key{ID: k.ID, Value: base64.StdEncoding.EncodeToString(k.Material)}, k.Association, nil)
		s.Keys[k.ID] = r
		s.Order = append(s.Order, k.ID)
		return nil
	})
}
func enqueue(s *state, peer string, r *record, status string) {
	if peer == "" {
		return
	}
	// At most one pending result per key/peer. Repeated transfer/ACK requests
	// regenerate that result without restoring consumed material.
	for id, j := range s.Acks {
		if j.Peer == peer && j.keyID() == r.ID {
			if j.Ack.Status == status {
				return
			}
			delete(s.Acks, id)
		}
	}
	s.Acks[core.NewID()] = ackJob{Peer: peer, Ack: etsi020.Ack{IDs: []etsi020.KeyRef{{ID: r.ID}}, Status: status, Initiator: r.Pair.Master, Targets: []string{r.Pair.Slave}}}
}
func (e *Engine) Accept(peer string, t etsi020.Transfer) error {
	if err := t.Validate(); err != nil {
		return err
	}
	p, ok := e.cfg.Peers[peer]
	if !ok || !p.Incoming || t.Callback != p.URL+peering.Base(p.Mode)+"/ack" {
		return core.ErrUnauthorized
	}
	a := core.Association{Master: t.Initiator, Slave: t.Targets[0]}
	if !e.allowed[a] || e.local(a.Master) {
		return core.ErrUnauthorized
	}
	return e.change(func(s *state) error {
		newCount := 0
		for _, k := range t.Keys {
			if r, ok := s.Keys[k.ID]; ok {
				if r.Sender != peer || r.Pair != a {
					return core.ErrUnauthorized
				}
				if !r.Unknown && r.Digest != digest(k, a, t.Optional) {
					return core.ErrDuplicate
				}
			} else {
				newCount++
			}
		}
		if len(s.Keys)+newCount > e.capacity {
			return core.ErrCapacity
		}
		for _, k := range t.Keys {
			if r, ok := s.Keys[k.ID]; ok {
				if !r.Voiding && !e.now().Before(r.Expires) {
					startVoid(s, r, peer)
				}
				if r.Voiding {
					finishVoid(s, r)
				} else if r.Ready {
					enqueue(s, peer, r, "relayed")
				}
				continue
			}
			material, _ := base64.StdEncoding.DecodeString(k.Value)
			r := &record{ID: k.ID, Pair: a, Sender: peer, Role: "relay", Material: material, Digest: digest(k, a, t.Optional), KeyExtension: cloneExtension(k.Extension), Optional: cloneExtension(t.Optional), Created: e.now(), Expires: e.now().Add(time.Hour)}
			if e.local(a.Slave) {
				r.Role = "target"
				r.Ready = true
				enqueue(s, peer, r, "relayed")
			} else {
				r.Candidates = e.candidates(s, a.Slave, peer)
				if len(r.Candidates) == 0 {
					return core.ErrUnavailable
				}
			}
			s.Keys[k.ID] = r
			s.Order = append(s.Order, k.ID)
		}
		return nil
	})
}
func (e *Engine) Acknowledge(peer string, acks []etsi020.Ack) error {
	if _, ok := e.cfg.Peers[peer]; !ok {
		return core.ErrUnauthorized
	}
	if err := etsi020.ValidateAcks(acks); err != nil {
		return err
	}
	return e.change(func(s *state) error {
		for _, a := range acks {
			for _, id := range a.IDs {
				r := s.Keys[id.ID]
				if r == nil || r.Pair.Master != a.Initiator || r.Pair.Slave != a.Targets[0] || (r.Next != peer && !(r.Voiding && r.Sender == peer)) {
					return core.ErrUnauthorized
				}
				if a.Status == "relayed" && (!r.Sent || peer != r.Next) {
					return core.ErrUnauthorized
				}
			}
		}
		for _, a := range acks {
			for _, id := range a.IDs {
				r := s.Keys[id.ID]
				if !r.Voiding && !e.now().Before(r.Expires) {
					startVoid(s, r, "")
				}
				if r.Voiding {
					if a.Status == "voided" || a.Status == "key not present" || a.Status == "failed to void" {
						delete(r.VoidPending, peer)
						r.VoidFailed = r.VoidFailed || a.Status == "failed to void"
						finishVoid(s, r)
					}
					continue
				}
				if a.Status == "relayed" {
					r.Ready = true
					if r.Role == "relay" {
						clear(r.Material)
						r.Material = nil
					}
					enqueue(s, r.Sender, r, "relayed")
				} else {
					startVoid(s, r, "")
					finishVoid(s, r)
				}
			}
		}
		return nil
	})
}
func startVoid(s *state, r *record, requester string) {
	if !r.Voiding {
		r.Voiding = true
		r.Ready = false
		r.Token = ""
		r.VoidFailed = r.Delivered
		r.Retry = time.Time{}
		clear(r.Material)
		r.Material = nil
		r.VoidPending = map[string]bool{}
		r.VoidRequests = map[string]bool{}
		if r.Sent {
			r.VoidPending[r.Next] = true
		}
		if r.Sender != "" {
			r.VoidPending[r.Sender] = true
		}
		for id, j := range s.Acks {
			if j.keyID() == r.ID {
				delete(s.Acks, id)
			}
		}
	}
	if requester != "" {
		r.VoidRequests[requester] = true
		delete(r.VoidPending, requester)
	}
}
func finishVoid(s *state, r *record) {
	if len(r.VoidPending) > 0 {
		return
	}
	status := "voided"
	if r.Unknown {
		status = "key not present"
	}
	if r.VoidFailed {
		status = "failed to void"
	}
	for peer := range r.VoidRequests {
		enqueue(s, peer, r, status)
	}
}
func (e *Engine) Void(peer string, v etsi020.Void) error {
	if err := v.Validate(); err != nil {
		return err
	}
	p, ok := e.cfg.Peers[peer]
	if !ok || v.Callback != p.URL+peering.Base(p.Mode)+"/ack" {
		return core.ErrUnauthorized
	}
	a := core.Association{Master: v.Initiator, Slave: v.Targets[0]}
	if !e.allowed[a] {
		return core.ErrUnauthorized
	}
	return e.change(func(s *state) error {
		ids := slices.Clone(v.IDs)
		if len(ids) == 0 {
			for _, id := range s.Order {
				r := s.Keys[id]
				if r.Pair == a && (r.Sender == peer || r.Next == peer) {
					ids = append(ids, id)
				}
			}
		}
		if len(ids) == 0 {
			for _, j := range s.Acks {
				if j.Peer == peer && len(j.Ack.IDs) == 0 && j.Ack.Initiator == a.Master && j.Ack.Targets[0] == a.Slave {
					return nil
				}
			}
			s.Acks[core.NewID()] = ackJob{Peer: peer, Ack: etsi020.Ack{IDs: []etsi020.KeyRef{}, Status: "key not present", Initiator: a.Master, Targets: []string{a.Slave}}}
			return nil
		}
		newCount := 0
		for _, id := range ids {
			r := s.Keys[id]
			if r == nil {
				if !p.Incoming {
					return core.ErrUnauthorized
				}
				newCount++
			} else if r.Pair != a || (r.Sender != peer && r.Next != peer) {
				return core.ErrUnauthorized
			}
		}
		if len(s.Keys)+newCount > e.capacity {
			return core.ErrCapacity
		}
		for _, id := range ids {
			r := s.Keys[id]
			if r == nil {
				r = &record{ID: id, Pair: a, Sender: peer, Unknown: true, Created: e.now(), Expires: e.now()}
				if e.local(a.Slave) {
					r.Role = "target"
				} else {
					r.Role = "relay"
				}
				s.Keys[id] = r
				s.Order = append(s.Order, id)
			}
			startVoid(s, r, peer)
			finishVoid(s, r)
		}
		return nil
	})
}

func usable(r *record, now time.Time) bool {
	return r.Ready && !r.Voiding && !r.Delivered && now.Before(r.Expires) && len(r.Material) == core.KeyBits/8
}
func (e *Engine) ReserveKeys(a core.Association, n int) (out core.Reservation, err error) {
	if n < 1 || n > core.MaxBatch {
		return out, core.ErrInvalid
	}
	err = e.change(func(s *state) error {
		if !e.allowed[a] || !e.local(a.Master) {
			return core.ErrUnauthorized
		}
		for _, id := range s.Order {
			r := s.Keys[id]
			if r.Pair == a && r.Role == "source" && r.Token == "" && usable(r, e.now()) {
				out.IDs = append(out.IDs, id)
				if len(out.IDs) == n {
					break
				}
			}
		}
		if len(out.IDs) != n {
			return core.ErrUnavailable
		}
		out.Token = core.NewID()
		for _, id := range out.IDs {
			s.Keys[id].Token = out.Token
		}
		return nil
	})
	if err != nil {
		out = core.Reservation{}
	}
	return
}
func (e *Engine) ConsumeReservation(a core.Association, token core.KeyID) (out []core.Delivery, err error) {
	if !token.Valid() {
		return nil, core.ErrInvalid
	}
	err = e.change(func(s *state) error {
		for _, id := range s.Order {
			r := s.Keys[id]
			if r.Token != token {
				continue
			}
			if r.Pair != a || r.Role != "source" {
				return core.ErrUnauthorized
			}
			if !usable(r, e.now()) {
				return core.ErrUnavailable
			}
			out = append(out, core.Delivery{ID: id, Material: slices.Clone(r.Material)})
		}
		if len(out) == 0 {
			return core.ErrUnavailable
		}
		for _, d := range out {
			r := s.Keys[d.ID]
			r.Delivered = true
			r.Token = ""
			clear(r.Material)
			r.Material = nil
		}
		return nil
	})
	if err != nil {
		for _, d := range out {
			clear(d.Material)
		}
		out = nil
	}
	return
}
func (e *Engine) ConsumePeerKeys(a core.Association, ids []core.KeyID) (out []core.Delivery, err error) {
	if len(ids) < 1 || len(ids) > core.MaxBatch {
		return nil, core.ErrInvalid
	}
	seen := map[core.KeyID]bool{}
	for _, id := range ids {
		if !id.Valid() || seen[id] {
			return nil, core.ErrInvalid
		}
		seen[id] = true
	}
	err = e.change(func(s *state) error {
		if !e.allowed[a] || !e.local(a.Slave) {
			return core.ErrUnauthorized
		}
		for _, id := range ids {
			r := s.Keys[id]
			if r == nil {
				return core.ErrUnavailable
			}
			if r.Pair != a || r.Role != "target" {
				return core.ErrUnauthorized
			}
			if !usable(r, e.now()) {
				return core.ErrUnavailable
			}
		}
		for _, id := range ids {
			r := s.Keys[id]
			out = append(out, core.Delivery{ID: id, Material: slices.Clone(r.Material)})
			r.Delivered = true
			clear(r.Material)
			r.Material = nil
		}
		return nil
	})
	if err != nil {
		for _, d := range out {
			clear(d.Material)
		}
		out = nil
	}
	return
}
func (e *Engine) InvalidateKey(id core.KeyID) error {
	return e.change(func(s *state) error {
		r := s.Keys[id]
		if r == nil {
			return core.ErrUnavailable
		}
		startVoid(s, r, "")
		finishVoid(s, r)
		return nil
	})
}
func (e *Engine) Inventory(a core.Association) core.Inventory {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := core.Inventory{Capacity: e.capacity}
	if e.broken {
		return out
	}
	for _, r := range e.s.Keys {
		if r.Pair == a && r.Role == "source" && r.Token == "" && usable(r, e.now()) {
			out.Available++
		}
	}
	return out
}
func (e *Engine) Metadata(id core.KeyID) (core.Metadata, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.broken {
		return core.Metadata{}, errJournal
	}
	r := e.s.Keys[id]
	if r == nil {
		return core.Metadata{}, core.ErrUnavailable
	}
	m := core.Metadata{ID: id, Association: r.Pair, Source: r.Role, CreatedAt: r.Created, ExpiresAt: r.Expires, MasterState: core.Reserved, SlaveState: core.Reserved}
	st := core.Reserved
	if usable(r, e.now()) {
		st = core.Available
	}
	if r.Voiding {
		st = core.Invalid
	}
	if !e.now().Before(r.Expires) {
		st = core.Expired
	}
	if r.Delivered {
		st = core.Consumed
	}
	if r.Role == "source" {
		m.MasterState = st
	} else if r.Role == "target" {
		m.SlaveState = st
	}
	return m, nil
}

// Snapshot exposes only operational metadata, never material or extensions.
type Snapshot struct {
	Records, Ready, Delivered, Voiding, PendingAcks int
	Paths                                           map[string]int
}

func (e *Engine) Snapshot() Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := Snapshot{Records: len(e.s.Keys), PendingAcks: len(e.s.Acks), Paths: map[string]int{}}
	for _, r := range e.s.Keys {
		if r.Ready {
			out.Ready++
		}
		if r.Delivered {
			out.Delivered++
		}
		if r.Voiding {
			out.Voiding++
		}
		if r.Sent {
			out.Paths[r.Next]++
		}
	}
	return out
}

func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.Step(ctx)
		}
	}
}

// Step drains a bounded snapshot of the outbox. It serializes workers, but
// releases the state lock before network I/O so callbacks can always progress.
func (e *Engine) Step(ctx context.Context) {
	e.step.Lock()
	defer e.step.Unlock()
	e.mu.Lock()
	if e.broken {
		e.mu.Unlock()
		return
	}
	var expired bool
	for _, r := range e.s.Keys {
		if !r.Voiding && !e.now().Before(r.Expires) {
			expired = true
			break
		}
	}
	e.mu.Unlock()
	if expired {
		if e.change(func(s *state) error {
			for _, r := range s.Keys {
				if !r.Voiding && !e.now().Before(r.Expires) {
					startVoid(s, r, "")
					finishVoid(s, r)
				}
			}
			return nil
		}) != nil {
			return
		}
	}
	e.mu.Lock()
	ids := slices.Clone(e.s.Order)
	jobs := make(map[core.KeyID]ackJob, len(e.s.Acks))
	for id, j := range e.s.Acks {
		jobs[id] = j
	}
	e.mu.Unlock()
	for id, j := range jobs {
		if ctx.Err() != nil {
			return
		}
		if e.now().Before(j.Retry) {
			continue
		}
		err := e.transport.Ack(ctx, j.Peer, []etsi020.Ack{j.Ack})
		_ = e.change(func(s *state) error {
			current, ok := s.Acks[id]
			if !ok {
				return nil
			}
			if err == nil {
				delete(s.Acks, id)
			} else {
				current.Retry = e.now().Add(e.retry)
				s.Acks[id] = current
			}
			return nil
		})
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		e.sendRecord(ctx, id)
	}
}
func (e *Engine) sendRecord(ctx context.Context, id core.KeyID) {
	e.mu.Lock()
	if e.broken {
		e.mu.Unlock()
		return
	}
	raw, _ := json.Marshal(e.s.Keys[id])
	e.mu.Unlock()
	var r record
	_ = json.Unmarshal(raw, &r)
	clear(raw)
	defer clear(r.Material)
	if e.now().Before(r.Retry) {
		return
	}
	if r.Voiding {
		for peer := range r.VoidPending {
			p := e.cfg.Peers[peer]
			v := etsi020.Void{IDs: []core.KeyID{id}, Initiator: r.Pair.Master, Targets: []string{r.Pair.Slave}, Callback: e.cfg.PublicURL + peering.Base(p.Mode) + "/ack"}
			_ = e.transport.Void(ctx, peer, v)
		}
		if len(r.VoidPending) > 0 {
			_ = e.change(func(s *state) error { s.Keys[id].Retry = e.now().Add(e.retry); return nil })
		}
		return
	}
	if r.Ready || r.Delivered || r.Role == "target" {
		return
	}
	peer := r.Next
	if !r.Sent {
		for _, candidate := range r.Candidates {
			if e.transport.Probe(ctx, candidate) == nil {
				peer = candidate
				break
			}
		}
		if peer == "" {
			_ = e.change(func(s *state) error { s.Keys[id].Retry = e.now().Add(e.retry); return nil })
			return
		}
	}
	// Persist uncertainty BEFORE the POST; a crash here must pin this key to
	// this peer even if the process cannot tell whether any bytes were sent.
	err := e.change(func(s *state) error {
		current := s.Keys[id]
		if current.Voiding || current.Ready || !e.now().Before(current.Expires) {
			return core.ErrUnavailable
		}
		current.Next = peer
		current.Sent = true
		current.Retry = e.now().Add(e.retry)
		return nil
	})
	if err != nil {
		return
	}
	p := e.cfg.Peers[peer]
	t := etsi020.Transfer{Keys: []etsi020.Key{{ID: id, Value: base64.StdEncoding.EncodeToString(r.Material), Extension: r.KeyExtension}}, Initiator: r.Pair.Master, Targets: []string{r.Pair.Slave}, Callback: e.cfg.PublicURL + peering.Base(p.Mode) + "/ack", Optional: r.Optional}
	_ = e.transport.Send(ctx, peer, t)
}
