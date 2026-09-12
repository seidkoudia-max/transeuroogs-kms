// Package metadata records material-free observations of committed KMS state.
package metadata

import (
	"errors"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"net/url"
	"strings"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
)

const Profile = "transeuroogs-metadata-v1"
const SnapshotField = "Provenance"
const MaxPage = 64
const MaxSnapshotBytes = 64 << 20

var ErrEvidence = errors.New("invalid metadata evidence")

type Config struct {
	Domain             string                        `json:"domain"`
	Issuer             string                        `json:"issuer"`
	Namespace          string                        `json:"namespace"`
	CredentialID       string                        `json:"credential_id"`
	SigningKeyFile     string                        `json:"signing_key_file"`
	StateDir           string                        `json:"state_dir,omitempty"`
	MaxEvents          int                           `json:"max_events"`
	ClockUncertaintyMS *int64                        `json:"clock_uncertainty_ms"`
	Readers            map[string][]core.Association `json:"readers"`
}

func name(s string) bool {
	return len(s) > 0 && len(s) <= 128 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}

func (c Config) Validate() error {
	u, e := url.Parse(c.Issuer)
	if e != nil || u.Scheme != "urn" || u.Opaque == "" || !name(c.Issuer) || !name(c.Domain) || !name(c.Namespace) || !name(c.CredentialID) || c.SigningKeyFile == "" || c.MaxEvents < 1 || c.MaxEvents > 100000 {
		return core.ErrInvalid
	}
	if c.ClockUncertaintyMS != nil && (*c.ClockUncertaintyMS < 0 || *c.ClockUncertaintyMS > 60000) {
		return core.ErrInvalid
	}
	for identity, pairs := range c.Readers {
		u, e := url.Parse(identity)
		if e != nil || u.Scheme != "urn" || u.Opaque == "" || len(pairs) == 0 {
			return core.ErrInvalid
		}
		seen := map[core.Association]bool{}
		for _, a := range pairs {
			if !a.Valid() || seen[a] {
				return core.ErrInvalid
			}
			seen[a] = true
		}
	}
	return nil
}

type KeyRef struct {
	Namespace   string           `json:"namespace"`
	ID          core.KeyID       `json:"key_id"`
	Association core.Association `json:"association"`
}

// Record is a projection: it cannot represent key bytes, fingerprints or tokens.
// Generation is populated only by the local synthetic source projection.
type Record struct {
	Key              KeyRef     `json:"key"`
	SourceClass      string     `json:"source_class"`
	SourceEvidence   string     `json:"source_evidence"`
	GenerationTime   *time.Time `json:"generation_time"`
	CollectionIntent time.Time  `json:"collection_intent"`
	LocalExpiresAt   time.Time  `json:"local_expires_at"`
	Role             string     `json:"role"`
	MasterState      core.State `json:"master_state,omitempty"`
	SlaveState       core.State `json:"slave_state,omitempty"`
	HoldingMaterial  bool       `json:"holding_material"`
	Upstream         string     `json:"upstream,omitempty"`
	NextPeer         string     `json:"next_peer,omitempty"`
	TransferIntent   bool       `json:"transfer_intent"`
	Ready            bool       `json:"ready"`
	Voiding          bool       `json:"voiding"`
	Uncertain        bool       `json:"uncertain"`
}

func (r Record) valid() bool {
	terminalUnknown := r.Uncertain && r.Voiding && !r.HoldingMaterial && r.SourceClass == "unknown" && r.LocalExpiresAt.Equal(r.CollectionIntent) && (r.Role == "relay" || (r.Role == "target" && r.SlaveState == core.Invalid))
	if !name(r.Key.Namespace) || !r.Key.ID.Valid() || !r.Key.Association.Valid() || r.CollectionIntent.IsZero() || (!r.LocalExpiresAt.After(r.CollectionIntent) && !terminalUnknown) {
		return false
	}
	if (r.Upstream != "" && !name(r.Upstream)) || (r.NextPeer != "" && !name(r.NextPeer)) {
		return false
	}
	if r.SourceClass == "synthetic" {
		if r.SourceEvidence != "local_observation" && r.SourceEvidence != "unverified_claim" {
			return false
		}
	} else if r.SourceClass != "unknown" || r.SourceEvidence != "unknown" {
		return false
	}
	if r.GenerationTime != nil && (r.GenerationTime.IsZero() || r.GenerationTime.After(r.CollectionIntent) || r.SourceEvidence != "local_observation") {
		return false
	}
	state := func(s core.State) bool {
		return s == core.Available || s == core.Reserved || s == core.Consumed || s == core.Expired || s == core.Invalid
	}
	switch r.Role {
	case "local":
		return state(r.MasterState) && state(r.SlaveState)
	case "source", "ingest_master":
		return state(r.MasterState) && r.SlaveState == ""
	case "target", "ingest_slave":
		return state(r.SlaveState) && r.MasterState == ""
	case "relay":
		return r.MasterState == "" && r.SlaveState == ""
	default:
		return false
	}
}

// Attempt.ID is an internal repository correlation value. Store replaces it
// with an independent UUID before creating any public event.
type Attempt struct {
	ID          string
	Association core.Association
	IDs         []core.KeyID
	Count       int
	Status      string
	Started     time.Time
}

type AttemptView struct {
	Reference   string           `json:"reference"`
	Association core.Association `json:"association"`
	IDs         []core.KeyID     `json:"known_key_ids"`
	Count       int              `json:"attempted_count"`
	Status      string           `json:"status"`
	Started     time.Time        `json:"started_at"`
}

func (a AttemptView) valid() bool {
	return core.KeyID(a.Reference).Valid() && a.validFields()
}

func (a AttemptView) validFields() bool {
	if !a.Association.Valid() || a.Count < 1 || a.Count > core.MaxBatch || len(a.IDs) > a.Count || a.Started.IsZero() {
		return false
	}
	seen := map[core.KeyID]bool{}
	for _, id := range a.IDs {
		if !id.Valid() || seen[id] {
			return false
		}
		seen[id] = true
	}
	switch a.Status {
	case "pending", "stored", "consumed", "uncertain":
		return true
	default:
		return false
	}
}

type Projection struct {
	Controls []allocation.Commit
	Keys     map[core.KeyID]Record
	Attempts map[string]Attempt
}

type Projector func([]byte) (Projection, error)

type Event struct {
	Profile            string             `json:"profile"`
	ID                 core.KeyID         `json:"event_id"`
	Domain             string             `json:"domain"`
	Issuer             string             `json:"issuer"`
	Sequence           uint64             `json:"sequence"`
	PreviousDigest     string             `json:"previous_digest"`
	PreviousKeyEvent   core.KeyID         `json:"previous_key_event,omitempty"`
	RecordedAt         time.Time          `json:"recorded_at"`
	ClockUncertaintyMS *int64             `json:"clock_uncertainty_ms"`
	Actions            []string           `json:"actions"`
	Record             *Record            `json:"record,omitempty"`
	Attempt            *AttemptView       `json:"attempt,omitempty"`
	Control            *allocation.Commit `json:"control,omitempty"`
}

func (e Event) onePayload() bool {
	n := 0
	if e.Record != nil {
		n++
	}
	if e.Attempt != nil {
		n++
	}
	if e.Control != nil {
		n++
	}
	return n == 1
}

type SignedEvent struct {
	Event Event  `json:"event"`
	JWS   string `json:"jws"`
}

type Page struct {
	Profile    string             `json:"profile"`
	Domain     string             `json:"domain"`
	Issuer     string             `json:"issuer"`
	Namespace  string             `json:"namespace"`
	Audience   string             `json:"audience"`
	StartedAt  time.Time          `json:"history_started_at"`
	ObservedAt time.Time          `json:"observed_at"`
	Watermark  uint64             `json:"watermark"`
	After      uint64             `json:"after"`
	Next       uint64             `json:"next"`
	Complete   bool               `json:"page_complete"`
	Scope      []core.Association `json:"scope"`
	Events     []SignedEvent      `json:"events"`
}

type SignedPage struct {
	Page Page   `json:"page"`
	JWS  string `json:"jws"`
}

type KeyView struct {
	Profile        string     `json:"profile"`
	Issuer         string     `json:"issuer"`
	Audience       string     `json:"audience"`
	Key            KeyRef     `json:"key"`
	SourceClass    string     `json:"source_class"`
	SourceEvidence string     `json:"source_evidence"`
	GenerationTime *time.Time `json:"generation_time"`
	LocalExpiresAt time.Time  `json:"local_expires_at"`
	State          core.State `json:"local_recipient_state,omitempty"`
	RecordedAt     time.Time  `json:"recorded_at"`
	HistoryStarted time.Time  `json:"history_started_at"`
	EvidenceScope  string     `json:"evidence_scope"`
}

type SignedKeyView struct {
	View KeyView `json:"view"`
	JWS  string  `json:"jws"`
}

func clone[T any](v T) T {
	b, _ := marshal(v)
	var out T
	_ = decode(b, &out)
	return out
}
