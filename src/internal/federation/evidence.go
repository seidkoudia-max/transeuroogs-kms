package federation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
)

const EvidenceProfile = "transeuroogs-provider-evidence-v1"
const evidenceType = "transeuroogs-provider-evidence+jws"

// Evidence is a project adapter's normalized statement. SES has not agreed to
// emit this schema. Only a configured, scoped signing key can assert these facts.
// There is deliberately no key material or key-derived fingerprint field.
type Evidence struct {
	Profile            string           `json:"profile"`
	ID                 core.KeyID       `json:"evidence_id"`
	Key                core.KeyID       `json:"key_id"`
	Issuer             string           `json:"issuer"`
	Pool               core.PoolRef     `json:"binding"`
	Gateways           core.Association `json:"gateway_pair"`
	Association        core.Association `json:"application_pair"`
	Origin             string           `json:"origin"`
	Kind               string           `json:"kind"`
	Ready              bool             `json:"relay_complete"`
	GeneratedAt        time.Time        `json:"generated_at"`
	IssuedAt           time.Time        `json:"issued_at"`
	ExpiresAt          time.Time        `json:"expires_at"`
	ClockUncertaintyMS int              `json:"clock_uncertainty_ms"`
	SigningKey         string           `json:"signing_key_id"`
	JWS                string           `json:"jws,omitempty"`
}

func exact(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return core.ErrInvalid
	}
	want, e := json.Marshal(out)
	var compact bytes.Buffer
	if e != nil || json.Compact(&compact, b) != nil || !bytes.Equal(want, compact.Bytes()) {
		return core.ErrInvalid
	}
	return nil
}
func (t Trust) public() (*ecdsa.PublicKey, error) {
	var j jose.JSONWebKey
	if json.Unmarshal(t.PublicJWK, &j) != nil || !j.IsPublic() || !j.Valid() || (j.Algorithm != "" && j.Algorithm != "ES256") || (j.Use != "" && j.Use != "sig") {
		return nil, core.ErrInvalid
	}
	p, ok := j.Key.(*ecdsa.PublicKey)
	if !ok || p.Curve != elliptic.P256() {
		return nil, core.ErrInvalid
	}
	return p, nil
}
func (t Trust) validate() error {
	if !identity(t.Issuer) || !name(t.KeyID) || len(t.PublicJWK) > 4096 || len(t.Services) == 0 {
		return core.ErrInvalid
	}
	for _, s := range t.Services {
		if !name(s) {
			return core.ErrInvalid
		}
	}
	b, e := time.Parse(time.RFC3339, t.NotBefore)
	a, f := time.Parse(time.RFC3339, t.NotAfter)
	if e != nil || f != nil || !a.After(b) {
		return core.ErrInvalid
	}
	_, e = t.public()
	return e
}

func (s *State) Verify(pool, token string, now time.Time) (Evidence, error) {
	p, ok := s.ByID(pool)
	if !ok || len(token) > 16384 || strings.Count(token, ".") != 2 {
		return Evidence{}, core.ErrInvalid
	}
	head, _, _ := strings.Cut(token, ".")
	raw, e := base64.RawURLEncoding.DecodeString(head)
	var header struct {
		Alg  string `json:"alg"`
		Key  string `json:"kid"`
		Type string `json:"typ"`
	}
	if e != nil || exact(raw, &header) != nil || header.Alg != "ES256" || header.Type != evidenceType {
		return Evidence{}, core.ErrInvalid
	}
	var trust *Trust
	for _, t := range s.Config.Trust {
		if t.KeyID == header.Key && t.Issuer == p.Provider && slices.Contains(t.Services, p.Ref.Service) && !t.Revoked {
			copy := t
			trust = &copy
			break
		}
	}
	if trust == nil {
		return Evidence{}, core.ErrUnauthorized
	}
	before, _ := time.Parse(time.RFC3339, trust.NotBefore)
	after, _ := time.Parse(time.RFC3339, trust.NotAfter)
	if now.Before(before) || !now.Before(after) {
		return Evidence{}, core.ErrUnauthorized
	}
	public, e := trust.public()
	if e != nil {
		return Evidence{}, e
	}
	obj, e := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.ES256})
	if e != nil || len(obj.Signatures) != 1 {
		return Evidence{}, core.ErrInvalid
	}
	// Exact protected-header parsing above excludes jku/jwk/x5u/crit and prevents
	// accepting attacker-selected keys or another local metadata signature type.
	payload, e := obj.Verify(public)
	var v Evidence
	if e != nil || exact(payload, &v) != nil || v.JWS != "" || v.Profile != EvidenceProfile || !v.ID.Valid() || !v.Key.Valid() || v.Issuer != p.Provider || v.SigningKey != header.Key || v.Pool != p.Ref || v.Gateways != p.Gateways || v.Association != p.Association || v.Kind != "final" || !v.Ready {
		return Evidence{}, core.ErrInvalid
	}
	if !slices.Contains([]string{"synthetic", "satellite", "terrestrial"}, v.Origin) || (p.Contract.Mode == "synthetic" && v.Origin != "synthetic") {
		return Evidence{}, core.ErrInvalid
	}
	if v.GeneratedAt.IsZero() || v.IssuedAt.Before(v.GeneratedAt) || v.IssuedAt.Before(before) || v.IssuedAt.After(now) || !v.ExpiresAt.After(now) || !v.ExpiresAt.After(v.IssuedAt) || v.ExpiresAt.After(after) || v.ClockUncertaintyMS < 0 || v.ClockUncertaintyMS > 60000 {
		return Evidence{}, core.ErrInvalid
	}
	if limit := p.Contract.ClockUncertaintyMS; limit != nil && v.ClockUncertaintyMS > *limit {
		return Evidence{}, core.ErrInvalid
	}
	if limit := p.Contract.MaxKeyAgeSeconds; limit != nil && v.ExpiresAt.Sub(v.GeneratedAt) > time.Duration(*limit)*time.Second {
		return Evidence{}, core.ErrInvalid
	}
	// A clock bound shortens usable validity; it never extends provider expiry.
	if !now.Add(time.Duration(v.ClockUncertaintyMS) * time.Millisecond).Before(v.ExpiresAt) {
		return Evidence{}, core.ErrUnavailable
	}
	v.JWS = token
	return v, nil
}

func (s *State) PutEvidence(pool, token string, now time.Time) error {
	v, e := s.Verify(pool, token, now)
	if e != nil {
		return e
	}
	if old, ok := s.Evidence[v.Key]; ok {
		if old.JWS != token {
			return ErrConflict
		}
		return nil
	}
	for _, old := range s.Evidence {
		if old.ID == v.ID {
			return ErrConflict
		}
	}
	if len(s.Evidence) >= 100000 {
		return core.ErrCapacity
	}
	s.Evidence[v.Key] = v
	return nil
}

// SignEvidence is provided for the synthetic provider and adapter tests. It uses
// RFC 7515 JWS / RFC 7518 ES256 from go-jose, not a bespoke signature primitive.
func SignEvidence(v Evidence, key *ecdsa.PrivateKey) (string, error) {
	if key == nil || key.Curve != elliptic.P256() || v.JWS != "" {
		return "", core.ErrInvalid
	}
	s, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType(evidenceType).WithHeader("kid", v.SigningKey))
	if e != nil {
		return "", e
	}
	b, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	signed, e := s.Sign(b)
	if e != nil {
		return "", e
	}
	return signed.CompactSerialize()
}
