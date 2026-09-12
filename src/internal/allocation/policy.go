// Package allocation owns material-free, locally enforced allocation policy.
// It has no HTTP, SDN controller, metadata signer or persistence dependency.
package allocation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
)

const Profile = "transeuroogs-allocation-v1"

var ErrConflict = errors.New("management revision or command conflict")
var ErrPolicy = errors.New("allocation policy denied")

type Rule struct {
	Paused                  bool     `json:"paused"`
	AllowedSources          []string `json:"allowed_sources"`
	AllowedIssuers          []string `json:"allowed_issuers"`
	RequireEvidence         bool     `json:"require_evidence"`
	AllowSatellite          bool     `json:"allow_satellite"`
	MaxGenerationAgeSeconds uint32   `json:"max_generation_age_seconds"`
	MaxLocalAgeSeconds      uint32   `json:"max_local_age_seconds"`
	MaxKeysPerRequest       int      `json:"max_keys_per_request"`
}

func Name(s string) bool {
	return len(s) > 0 && len(s) <= 128 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}
func URI(s string) bool {
	u, e := url.Parse(s)
	return e == nil && u.Scheme == "urn" && u.Opaque != "" && Name(s)
}
func (r Rule) Valid() bool {
	if r.MaxKeysPerRequest < 1 || r.MaxKeysPerRequest > core.MaxBatch || r.MaxGenerationAgeSeconds > 2678400 || r.MaxLocalAgeSeconds > 2678400 || len(r.AllowedSources) == 0 || len(r.AllowedSources) > 4 || len(r.AllowedIssuers) > 64 {
		return false
	}
	for i, s := range r.AllowedSources {
		if !slices.Contains([]string{"synthetic", "satellite", "terrestrial", "unknown"}, s) || slices.Contains(r.AllowedSources[:i], s) {
			return false
		}
	}
	for i, s := range r.AllowedIssuers {
		if !URI(s) || slices.Contains(r.AllowedIssuers[:i], s) {
			return false
		}
	}
	return true
}

type Facts struct {
	Source, Issuer, Evidence string
	Generation               *time.Time
	Collected, Expires       time.Time
	ClockUncertaintyMS       *int64
}

// Evaluate returns a bounded reason code. Time-sensitive checks run again at
// delivery under the repository lock, including already-reserved batches.
func Evaluate(r Rule, f Facts, now time.Time) string {
	if r.Paused {
		return "paused"
	}
	if !slices.Contains(r.AllowedSources, f.Source) {
		return "source_denied"
	}
	if f.Source == "satellite" && !r.AllowSatellite {
		return "satellite_not_entitled"
	}
	if len(r.AllowedIssuers) > 0 && !slices.Contains(r.AllowedIssuers, f.Issuer) {
		return "issuer_denied"
	}
	if r.RequireEvidence && f.Evidence != "local_observation" && f.Evidence != "verified_claim" {
		return "evidence_unknown"
	}
	if !f.Expires.IsZero() && !now.Before(f.Expires) {
		return "expired"
	}
	if r.MaxLocalAgeSeconds > 0 {
		if f.Collected.IsZero() || f.Collected.After(now) {
			return "collection_time_unknown"
		}
		if now.Sub(f.Collected) > time.Duration(r.MaxLocalAgeSeconds)*time.Second {
			return "local_age_exceeded"
		}
	}
	if r.MaxGenerationAgeSeconds > 0 {
		if f.Generation == nil || f.Generation.IsZero() || f.ClockUncertaintyMS == nil || *f.ClockUncertaintyMS < 0 || *f.ClockUncertaintyMS > 60000 || (f.Evidence != "local_observation" && f.Evidence != "verified_claim") {
			return "generation_time_unknown"
		}
		uncertainty := time.Duration(*f.ClockUncertaintyMS) * time.Millisecond
		if f.Generation.Add(-uncertainty).After(now.Add(uncertainty)) {
			return "generation_time_unknown"
		}
		if now.Add(uncertainty).Sub(f.Generation.Add(-uncertainty)) > time.Duration(r.MaxGenerationAgeSeconds)*time.Second {
			return "generation_age_exceeded"
		}
	}
	return ""
}

type Binding struct {
	AppID        core.KeyID       `json:"app_id"`
	Association  core.Association `json:"association"`
	RemoteNodeID core.KeyID       `json:"remote_node_id"`
	Rule         Rule             `json:"rule"`
}
type Principal struct {
	Pairs  []core.Association `json:"associations"`
	Write  bool               `json:"write"`
	Routes bool               `json:"routes"`
}
type Config struct {
	NodeID      core.KeyID           `json:"node_id"`
	Location    string               `json:"location"`
	Apps        []Binding            `json:"applications"`
	Principals  map[string]Principal `json:"principals"`
	MaxCommands int                  `json:"max_commands"`
}

func (c Config) Validate(pairs []core.Association) error {
	if !c.NodeID.Valid() || !Name(c.Location) || c.MaxCommands < 1 || c.MaxCommands > 10000 || len(c.Apps) != len(pairs) || len(c.Apps) > 64 || len(c.Principals) < 1 || len(c.Principals) > 64 {
		return core.ErrInvalid
	}
	seen := map[core.Association]bool{}
	ids := map[core.KeyID]bool{}
	for _, a := range c.Apps {
		if !a.AppID.Valid() || !a.Association.Valid() || !a.RemoteNodeID.Valid() || !a.Rule.Valid() || !slices.Contains(pairs, a.Association) || seen[a.Association] || ids[a.AppID] {
			return core.ErrInvalid
		}
		seen[a.Association] = true
		ids[a.AppID] = true
	}
	for id, p := range c.Principals {
		if !URI(id) || len(p.Pairs) == 0 || len(p.Pairs) > len(pairs) || (!p.Write && p.Routes) {
			return core.ErrInvalid
		}
		for i, a := range p.Pairs {
			if !seen[a] || slices.Contains(p.Pairs[:i], a) {
				return core.ErrInvalid
			}
		}
	}
	return nil
}

// Setup is assembled locally. Controllers cannot change identities, peer URLs,
// trust roots, source assertions, or the catalog of permitted routes.
type Setup struct {
	Config             Config
	Issuer             string
	ClockUncertaintyMS *int64
	Routes             map[string][]string
}
type Command struct {
	ID               core.KeyID       `json:"command_id"`
	ExpectedRevision uint64           `json:"expected_revision"`
	Association      core.Association `json:"association"`
	Rule             *Rule            `json:"rule,omitempty"`
	Routes           []string         `json:"routes,omitempty"`
	LocalTTL         *uint32          `json:"local_ttl_seconds,omitempty"`
}

func (c Command) Valid() bool {
	if !c.ID.Valid() || !c.Association.Valid() || (c.Rule == nil && len(c.Routes) == 0 && c.LocalTTL == nil) || (c.Rule != nil && !c.Rule.Valid()) || len(c.Routes) > 64 || (c.LocalTTL != nil && (c.Rule != nil || *c.LocalTTL > 2678400)) {
		return false
	}
	for i, p := range c.Routes {
		if !Name(p) || slices.Contains(c.Routes[:i], p) {
			return false
		}
	}
	return true
}

type Commit struct {
	Command   Command   `json:"command"`
	Actor     string    `json:"actor"`
	Revision  uint64    `json:"revision"`
	AppliedAt time.Time `json:"applied_at"`
}

func (c Commit) Valid() bool {
	return c.Command.Valid() && URI(c.Actor) && c.Revision == c.Command.ExpectedRevision+1 && c.Revision > 0 && !c.AppliedAt.IsZero()
}

type State struct {
	Profile  string              `json:"profile"`
	Binding  string              `json:"binding"`
	Revision uint64              `json:"revision"`
	Apps     []Binding           `json:"applications"`
	Routes   map[string][]string `json:"routes"`
	Commits  []Commit            `json:"commits"`
}

func Clone[T any](v T) T { b, _ := json.Marshal(v); var out T; _ = json.Unmarshal(b, &out); return out }

// Open refuses silently enabling or disabling policy on established state.
// Bootstrap configuration is immutable; runtime changes are replayed from the
// same encrypted snapshot as key state.
func Open(setup *Setup, saved *State, established bool) (*State, error) {
	if setup == nil {
		if saved != nil {
			return nil, core.ErrInvalid
		}
		return nil, nil
	}
	pairs := []core.Association{}
	for _, b := range setup.Config.Apps {
		pairs = append(pairs, b.Association)
	}
	if setup.Config.Validate(pairs) != nil || !URI(setup.Issuer) || (setup.ClockUncertaintyMS != nil && (*setup.ClockUncertaintyMS < 0 || *setup.ClockUncertaintyMS > 60000)) {
		return nil, core.ErrInvalid
	}
	bound := Clone(*setup)
	bound.Config.Principals = nil
	bytes, _ := json.Marshal(bound)
	hash := sha256.Sum256(bytes)
	s := &State{Profile: Profile, Binding: hex.EncodeToString(hash[:]), Apps: Clone(setup.Config.Apps), Routes: Clone(setup.Routes), Commits: []Commit{}}
	if saved == nil {
		if established {
			return nil, core.ErrInvalid
		}
		return s, nil
	}
	if saved.Profile != Profile || saved.Binding != s.Binding || len(saved.Commits) > setup.Config.MaxCommands || saved.Revision != uint64(len(saved.Commits)) {
		return nil, core.ErrInvalid
	}
	for _, c := range saved.Commits {
		if !c.Valid() {
			return nil, core.ErrInvalid
		}
		if _, e := s.Apply(setup, c.Actor, c.Command, c.AppliedAt); e != nil {
			return nil, e
		}
	}
	if !reflect.DeepEqual(s, saved) {
		return nil, core.ErrInvalid
	}
	return s, nil
}
func Select(options []*Setup) *Setup {
	if len(options) == 1 {
		return Clone(options[0])
	}
	return nil
}

// Authorize is also checked by repositories, independently of HTTP adapters.
// Recovery replays historical commands without requiring an actor still to hold
// its former permissions; revocation affects all new calls, including retries.
func Authorize(setup *Setup, actor string, c Command) error {
	if setup == nil {
		return core.ErrUnauthorized
	}
	p, ok := setup.Config.Principals[actor]
	if !ok || !p.Write || !slices.Contains(p.Pairs, c.Association) || (len(c.Routes) > 0 && !p.Routes) {
		return core.ErrUnauthorized
	}
	return nil
}
func (s *State) Rule(a core.Association) (Rule, bool) {
	if s == nil {
		return Rule{}, false
	}
	for _, b := range s.Apps {
		if b.Association == a {
			return b.Rule, true
		}
	}
	return Rule{}, false
}
func (s *State) Check(a core.Association, n int, f Facts, now time.Time) string {
	if s == nil {
		return ""
	}
	r, ok := s.Rule(a)
	if !ok {
		return "association_denied"
	}
	if n > r.MaxKeysPerRequest {
		return "batch_limit"
	}
	return Evaluate(r, f, now)
}
func (s *State) Apply(setup *Setup, actor string, c Command, now time.Time) (Commit, error) {
	if s == nil || setup == nil || !URI(actor) || !c.Valid() {
		return Commit{}, core.ErrInvalid
	}
	for _, old := range s.Commits {
		if old.Command.ID == c.ID {
			if old.Actor != actor || !reflect.DeepEqual(old.Command, c) {
				return Commit{}, ErrConflict
			}
			return Clone(old), nil
		}
	}
	if c.ExpectedRevision != s.Revision {
		return Commit{}, ErrConflict
	}
	if len(s.Commits) >= setup.Config.MaxCommands {
		return Commit{}, core.ErrCapacity
	}
	if len(s.Commits) > 0 && now.Before(s.Commits[len(s.Commits)-1].AppliedAt) {
		return Commit{}, core.ErrInvalid
	}
	index := -1
	for i, b := range s.Apps {
		if b.Association == c.Association {
			index = i
		}
	}
	if index < 0 {
		return Commit{}, core.ErrUnauthorized
	}
	if len(c.Routes) > 0 {
		for _, peer := range c.Routes {
			if !slices.Contains(setup.Routes[c.Association.Slave], peer) {
				return Commit{}, core.ErrUnauthorized
			}
		}
		// Routing is per destination SAE; don't alter another association's route.
		for _, b := range s.Apps {
			if b.Association != c.Association && b.Association.Slave == c.Association.Slave {
				return Commit{}, core.ErrInvalid
			}
		}
	}
	if c.Rule != nil {
		s.Apps[index].Rule = Clone(*c.Rule)
	}
	if c.LocalTTL != nil {
		s.Apps[index].Rule.MaxLocalAgeSeconds = *c.LocalTTL
	}
	if len(c.Routes) > 0 {
		s.Routes[c.Association.Slave] = slices.Clone(c.Routes)
	}
	s.Revision++
	result := Commit{Clone(c), actor, s.Revision, now.UTC()}
	s.Commits = append(s.Commits, result)
	return Clone(result), nil
}

// Known synthetic origin is generated locally. Unknown/provider-origin material
// must not acquire a generation timestamp from its collection timestamp.
func LocalFacts(source string, created, expires time.Time, setup *Setup) Facts {
	f := Facts{Source: "unknown", Evidence: "unknown", Collected: created, Expires: expires}
	if source == "synthetic-qkd" {
		f.Source = "synthetic"
		f.Evidence = "local_observation"
		f.Generation = &created
		if setup != nil {
			f.Issuer = setup.Issuer
			f.ClockUncertaintyMS = setup.ClockUncertaintyMS
		}
	}
	return f
}

type Counts struct {
	Capacity          int            `json:"capacity"`
	Available         int            `json:"available"`
	Eligible          int            `json:"eligible"`
	Reserved          int            `json:"reserved"`
	Delivered         int            `json:"delivery_commitments"`
	Denied            map[string]int `json:"denied_reasons"`
	InFlight          map[string]int `json:"in_flight_by_peer"`
	UpstreamAvailable *int           `json:"upstream_available"`
}
type AppView struct {
	Pool           core.PoolRef `json:"pool,omitzero"`
	ProtectionGate string       `json:"protection_gate,omitempty"`
	Binding
	Counts Counts   `json:"counts"`
	Routes []string `json:"routes"`
}
type View struct {
	Profile    string     `json:"profile"`
	NodeID     core.KeyID `json:"node_id"`
	Issuer     string     `json:"issuer"`
	Revision   uint64     `json:"revision"`
	ObservedAt time.Time  `json:"observed_at"`
	Apps       []AppView  `json:"applications"`
}

func (s *State) View(setup *Setup, pairs []core.Association, now time.Time) View {
	out := View{Profile: Profile, NodeID: setup.Config.NodeID, Issuer: setup.Issuer, Revision: s.Revision, ObservedAt: now.UTC(), Apps: []AppView{}}
	for _, b := range s.Apps {
		if slices.Contains(pairs, b.Association) {
			out.Apps = append(out.Apps, AppView{Binding: Clone(b), Routes: slices.Clone(s.Routes[b.Association.Slave]), Counts: Counts{Denied: map[string]int{}, InFlight: map[string]int{}}})
		}
	}
	return out
}

type Manager interface {
	ManagementView([]core.Association) (View, error)
	ApplyCommand(string, Command) (Commit, error)
}
