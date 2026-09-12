package federation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
)

var ErrConflict = errors.New("federation revision or action conflict")

type Command struct {
	ID               core.KeyID `json:"action_id"`
	Incident         core.KeyID `json:"incident_id"`
	Pool             string     `json:"pool_id"`
	ExpectedRevision uint64     `json:"expected_revision"`
	Operation        string     `json:"operation"` // hold | invalidate | release
	Reason           string     `json:"reason"`
}
type Result struct {
	Command          Command   `json:"command"`
	Actor            string    `json:"actor"`
	Revision         uint64    `json:"revision"`
	At               time.Time `json:"recorded_at"`
	Invalidated      int       `json:"invalidated_copies"`
	AlreadyDelivered int       `json:"already_delivered_copies"`
	RemoteStatus     string    `json:"remote_status"`
}
type Incident struct {
	ID          core.KeyID `json:"incident_id"`
	Pool        string     `json:"pool_id"`
	Held        bool       `json:"held"`
	Invalidated bool       `json:"invalidated"`
	Opened      time.Time  `json:"opened_at"`
}
type Receipt struct {
	ID          core.KeyID       `json:"receipt_id"`
	Session     core.KeyID       `json:"session_id"`
	Key         core.KeyID       `json:"key_id"`
	Pool        core.PoolRef     `json:"binding"`
	Association core.Association `json:"association"`
	SAE         string           `json:"sae_id"`
	Status      string           `json:"status"` // confirmed | retired | rekey_failed
	Incident    core.KeyID       `json:"incident_id,omitempty"`
	At          time.Time        `json:"recorded_at"`
}
type Reconciliation struct {
	ID      core.KeyID `json:"action_id"`
	Pool    string     `json:"pool_id"`
	Request core.KeyID `json:"request_reference"`
	Actor   string     `json:"actor"`
	Status  string     `json:"provider_status"`
	At      time.Time  `json:"recorded_at"`
}
type State struct {
	Config          Config                        `json:"config"`
	Binding         string                        `json:"binding"`
	Revision        uint64                        `json:"revision"`
	Actions         []Result                      `json:"actions"`
	Incidents       map[core.KeyID]Incident       `json:"incidents"`
	Receipts        map[core.KeyID]Receipt        `json:"receipts"`
	Reconciliations map[core.KeyID]Reconciliation `json:"reconciliations"`
	Evidence        map[core.KeyID]Evidence       `json:"evidence"`
}

func Open(c *Config, saved *State, established bool, pairs []core.Association) (*State, error) {
	if c == nil {
		if saved != nil {
			return nil, ErrConflict
		}
		return nil, nil
	}
	if c.Validate(pairs) != nil {
		return nil, core.ErrInvalid
	}
	// Active bindings and trust are immutable for this journal generation. A
	// changed file must not reinterpret historical keys or silently discard holds.
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	binding := hex.EncodeToString(h[:])
	if saved == nil {
		if established {
			return nil, ErrConflict
		}
		return &State{Config: Clone(*c), Binding: binding, Incidents: map[core.KeyID]Incident{}, Receipts: map[core.KeyID]Receipt{}, Reconciliations: map[core.KeyID]Reconciliation{}, Evidence: map[core.KeyID]Evidence{}}, nil
	}
	if saved.Binding != binding || !reflect.DeepEqual(saved.Config, Clone(*c)) || saved.Incidents == nil || saved.Receipts == nil || saved.Reconciliations == nil || saved.Evidence == nil || len(saved.Actions) > c.MaxActions || len(saved.Receipts) > c.MaxActions || len(saved.Reconciliations) > c.MaxActions || saved.Revision != uint64(len(saved.Actions)) {
		return nil, ErrConflict
	}
	// Replay the control history and compare the resulting holds, including
	// released incidents. A stale/mutated hold map cannot bypass the action log.
	check, _ := Open(c, nil, false, pairs)
	for _, r := range saved.Actions {
		out, e := check.Apply(r.Actor, r.Command, r.At)
		if e != nil || out.Revision != r.Revision {
			return nil, ErrConflict
		}
	}
	if !reflect.DeepEqual(check.Incidents, saved.Incidents) {
		return nil, ErrConflict
	}
	return Clone(saved), nil
}

func (s *State) Pool(a core.Association) (Pool, bool) {
	if s != nil {
		for _, p := range s.Config.Pools {
			if p.Association == a {
				return p, true
			}
		}
	}
	return Pool{}, false
}
func (s *State) ByID(id string) (Pool, bool) {
	if s != nil {
		for _, p := range s.Config.Pools {
			if p.Ref.ID == id {
				return p, true
			}
		}
	}
	return Pool{}, false
}
func (s *State) Ref(a core.Association) core.PoolRef { p, _ := s.Pool(a); return p.Ref }

func (s *State) Gate(a core.Association) string {
	if s == nil {
		return ""
	}
	p, ok := s.Pool(a)
	if !ok {
		return "unknown_pool"
	}
	if len(s.Actions) >= s.Config.MaxActions || len(s.Receipts) >= s.Config.MaxActions {
		return "maintenance_capacity_reached"
	}
	if p.Contract.Mode == "ses-pending" {
		return "needs_SES_input"
	}
	for _, i := range s.Incidents {
		if i.Pool == p.Ref.ID && i.Held {
			return "incident_hold"
		}
	}
	return ""
}
func (s *State) Check(a core.Association, id core.KeyID, now time.Time) string {
	if reason := s.Gate(a); reason != "" {
		return reason
	}
	p, ok := s.Pool(a)
	if !ok {
		return ""
	}
	e, has := s.Evidence[id]
	if p.RequireEvidence || p.MaxGenerationAgeSeconds > 0 {
		if !has {
			return "provider_evidence_required"
		}
	}
	if has {
		if !now.Add(time.Duration(e.ClockUncertaintyMS)*time.Millisecond).Before(e.ExpiresAt) || !e.Ready {
			return "provider_evidence_expired"
		}
		if p.MaxGenerationAgeSeconds > 0 && now.Sub(e.GeneratedAt)+time.Duration(e.ClockUncertaintyMS)*time.Millisecond > time.Duration(p.MaxGenerationAgeSeconds)*time.Second {
			return "provider_generation_too_old"
		}
	}
	return ""
}

func (s *State) Authorized(actor, pool string, write bool) bool {
	if s == nil {
		return false
	}
	g, ok := s.Config.Principals[actor]
	return ok && (!write || g.Operate) && slices.Contains(g.Pools, pool)
}
func (s *State) Apply(actor string, c Command, now time.Time) (Result, error) {
	if !s.Authorized(actor, c.Pool, true) {
		return Result{}, core.ErrUnauthorized
	}
	if !c.ID.Valid() || !c.Incident.Valid() || !name(c.Reason) || !slices.Contains([]string{"hold", "invalidate", "release"}, c.Operation) {
		return Result{}, core.ErrInvalid
	}
	for _, r := range s.Actions {
		if r.Command.ID == c.ID {
			if r.Actor != actor || r.Command != c {
				return Result{}, ErrConflict
			}
			return r, nil
		}
	}
	if c.ExpectedRevision != s.Revision {
		return Result{}, ErrConflict
	}
	if len(s.Actions) >= s.Config.MaxActions {
		return Result{}, core.ErrCapacity
	}
	if len(s.Actions) > 0 && now.Before(s.Actions[len(s.Actions)-1].At) {
		return Result{}, ErrConflict
	}
	i, exists := s.Incidents[c.Incident]
	if exists && i.Pool != c.Pool {
		return Result{}, ErrConflict
	}
	if !exists {
		if c.Operation == "release" {
			return Result{}, ErrConflict
		}
		i = Incident{ID: c.Incident, Pool: c.Pool, Opened: now}
	}
	switch c.Operation {
	case "hold":
		i.Held = true
	case "invalidate":
		i.Held = true
		i.Invalidated = true
	case "release":
		if !i.Held {
			return Result{}, ErrConflict
		}
		i.Held = false
	}
	s.Incidents[c.Incident] = i
	s.Revision++
	r := Result{Command: c, Actor: actor, Revision: s.Revision, At: now, RemoteStatus: "not_contacted"}
	s.Actions = append(s.Actions, r)
	return r, nil
}

// AddReceipt records an authenticated application's report, not proof that a
// commercial encryptor actually retired a key. The repository checks delivery.
func (s *State) AddReceipt(r Receipt, m core.Metadata, now time.Time) error {
	if s == nil {
		return core.ErrUnauthorized
	}
	if !r.ID.Valid() || !r.Session.Valid() || r.Key != m.ID || r.Association != m.Association || r.Pool != s.Ref(m.Association) || !slices.Contains([]string{"confirmed", "retired", "rekey_failed"}, r.Status) || !r.At.IsZero() {
		return core.ErrInvalid
	}
	if (r.SAE != m.Association.Master || m.MasterState != core.Consumed) && (r.SAE != m.Association.Slave || m.SlaveState != core.Consumed) {
		return core.ErrUnauthorized
	}
	if r.Incident != "" {
		i, ok := s.Incidents[r.Incident]
		if !ok || i.Pool != r.Pool.ID {
			return core.ErrInvalid
		}
	}
	if old, ok := s.Receipts[r.ID]; ok {
		old.At = time.Time{}
		if old != r {
			return ErrConflict
		}
		return nil
	}
	if len(s.Receipts) >= s.Config.MaxActions {
		return core.ErrCapacity
	}
	for _, old := range s.Receipts {
		if old.SAE == r.SAE && ((old.Session == r.Session && old.Key != r.Key) || (old.Key == r.Key && old.Session != r.Session)) {
			return ErrConflict
		}
		if old.SAE == r.SAE && old.Key == r.Key && old.Status == "retired" && r.Status != "retired" {
			return ErrConflict
		}
	}
	r.At = now
	s.Receipts[r.ID] = r
	return nil
}

type View struct {
	Profile         string           `json:"profile"`
	Revision        uint64           `json:"revision"`
	Pools           []PoolView       `json:"pools"`
	Incidents       []Incident       `json:"incidents"`
	Receipts        []Receipt        `json:"receipts,omitempty"`
	Reconciliations []Reconciliation `json:"reconciliations,omitempty"`
}
type PoolView struct {
	Pool   Pool          `json:"pool"`
	Gate   string        `json:"allocation_gate"`
	Needed []NeededInput `json:"needed_SES_input"`
}

func (s *State) View(pools []string, sae string) View {
	v := View{Profile: Profile}
	if s == nil {
		return v
	}
	v.Revision = s.Revision
	for _, p := range s.Config.Pools {
		if slices.Contains(pools, p.Ref.ID) {
			v.Pools = append(v.Pools, PoolView{p, s.Gate(p.Association), p.Contract.Needed()})
		}
	}
	for _, i := range s.Incidents {
		if slices.Contains(pools, i.Pool) {
			v.Incidents = append(v.Incidents, i)
		}
	}
	for _, r := range s.Receipts {
		if slices.Contains(pools, r.Pool.ID) && (sae == "" || sae == r.SAE) {
			v.Receipts = append(v.Receipts, r)
		}
	}
	if sae == "" {
		for _, r := range s.Reconciliations {
			if slices.Contains(pools, r.Pool) {
				v.Reconciliations = append(v.Reconciliations, r)
			}
		}
	}
	slices.SortFunc(v.Incidents, func(a, b Incident) int { return compare(string(a.ID), string(b.ID)) })
	slices.SortFunc(v.Receipts, func(a, b Receipt) int { return compare(string(a.ID), string(b.ID)) })
	slices.SortFunc(v.Reconciliations, func(a, b Reconciliation) int { return compare(string(a.ID), string(b.ID)) })
	return v
}
func compare(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

type Manager interface {
	ProtectionView([]string, string) (View, error)
	ApplyProtection(string, Command) (Result, error)
	RecordReceipt(Receipt) error
	ImportEvidence(string, string, string) error
}
