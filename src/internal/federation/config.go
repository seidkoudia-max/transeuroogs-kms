// Package federation implements local cross-domain protection controls. It does
// not synchronize satellite keys or define an SES transport protocol.
package federation

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
)

const Profile = "transeuroogs-federation-v1"

type Pool struct {
	Ref                     core.PoolRef     `json:"binding"`
	Domain                  string           `json:"domain_id"`
	OGS                     string           `json:"ogs_id"`
	RemoteDomain            string           `json:"remote_domain_id"`
	RemoteOGS               string           `json:"remote_ogs_id"`
	Association             core.Association `json:"association"`
	Provider                string           `json:"provider_identity"`
	Gateways                core.Association `json:"gateway_pair"`
	Mapping                 string           `json:"mapping_authority"` // synthetic-provisioning or SES agreement reference
	Contract                Contract         `json:"contract"`
	RequireEvidence         bool             `json:"require_provider_evidence"`
	MaxGenerationAgeSeconds int              `json:"max_generation_age_seconds"`
}

// Contract records unresolved inputs without silently substituting lab values.
// These are project configuration fields, not claimed SES API fields.
type Contract struct {
	Mode               string `json:"mode"` // synthetic | ses-pending | ses-reviewed
	Agreement          string `json:"interface_agreement,omitempty"`
	APIProfile         string `json:"api_profile,omitempty"`
	PoolSelection      string `json:"pool_selection,omitempty"`
	FinalRelease       string `json:"final_release_semantics,omitempty"`
	RetentionSeconds   *int   `json:"retention_seconds,omitempty"`
	MaxKeyAgeSeconds   *int   `json:"max_key_age_seconds,omitempty"`
	ClockUncertaintyMS *int   `json:"clock_uncertainty_ms,omitempty"`
	Recovery           string `json:"non_consuming_recovery,omitempty"`
	Evidence           string `json:"evidence_profile,omitempty"`
	TrustAgreement     string `json:"authentication_agreement,omitempty"`
}

type NeededInput struct {
	ID    string `json:"id"`
	Field string `json:"field"`
	Owner string `json:"owner"`
}

func (c Contract) Needed() []NeededInput {
	var out []NeededInput
	add := func(id, field string, missing bool) {
		if missing {
			out = append(out, NeededInput{id, field, "SES"})
		}
	}
	add("SES-I01", "interface_agreement", c.Agreement == "")
	add("SES-I02", "api_profile", c.APIProfile == "")
	add("SES-M17", "pool_selection", c.PoolSelection == "")
	add("SES-M18", "final_release_semantics", c.FinalRelease == "")
	add("SES-I05", "retention_seconds", c.RetentionSeconds == nil)
	add("SES-I06", "max_key_age_seconds", c.MaxKeyAgeSeconds == nil)
	add("SES-I07", "clock_uncertainty_ms", c.ClockUncertaintyMS == nil)
	add("SES-I08", "non_consuming_recovery", c.Recovery == "")
	add("SES-I09", "evidence_profile", c.Evidence == "")
	add("SES-I10", "authentication_agreement", c.TrustAgreement == "")
	return out
}

func (c Contract) valid() bool {
	if !slices.Contains([]string{"synthetic", "ses-pending", "ses-reviewed"}, c.Mode) {
		return false
	}
	for _, n := range []*int{c.RetentionSeconds, c.MaxKeyAgeSeconds} {
		if n != nil && (*n < 1 || *n > 2678400) {
			return false
		}
	}
	if c.ClockUncertaintyMS != nil && (*c.ClockUncertaintyMS < 0 || *c.ClockUncertaintyMS > 60000) {
		return false
	}
	for _, s := range []string{c.Agreement, c.APIProfile, c.PoolSelection, c.FinalRelease, c.Recovery, c.Evidence, c.TrustAgreement} {
		if s != "" && !name(s) {
			return false
		}
	}
	return c.Mode != "ses-reviewed" || len(c.Needed()) == 0
}

type Grant struct {
	Pools   []string `json:"pools"`
	Operate bool     `json:"operate"`
}

// A trust entry is an explicitly provisioned public JWK, with a bounded validity
// window. Its issuer/service scope cannot be widened by an incoming JWS header.
type Trust struct {
	Issuer    string          `json:"issuer"`
	KeyID     string          `json:"key_id"`
	PublicJWK json.RawMessage `json:"public_jwk"`
	Services  []string        `json:"services"`
	NotBefore string          `json:"not_before"`
	NotAfter  string          `json:"not_after"`
	Revoked   bool            `json:"revoked"`
}

type Config struct {
	Profile    string           `json:"profile"`
	StateDir   string           `json:"state_dir,omitempty"`
	Pools      []Pool           `json:"pools"`
	Principals map[string]Grant `json:"principals"`
	Trust      []Trust          `json:"provider_trust"`
	MaxActions int              `json:"max_actions"`
}

func name(s string) bool {
	return len(s) > 0 && len(s) <= 128 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\r\n\x00")
}
func identity(s string) bool {
	u, e := url.Parse(s)
	return name(s) && e == nil && u.Scheme == "urn" && u.Opaque != ""
}

func (c Config) Validate(pairs []core.Association) error {
	if c.Profile != Profile || len(c.Pools) < 1 || len(c.Pools) > 64 || c.MaxActions < 1 || c.MaxActions > 100000 {
		return core.ErrInvalid
	}
	seen, bound, gateways := map[string]bool{}, map[core.Association]bool{}, map[string]bool{}
	for _, p := range c.Pools {
		if !p.Ref.Valid() || !name(p.Domain) || !name(p.OGS) || !name(p.RemoteDomain) || !name(p.RemoteOGS) || !name(p.Mapping) || !identity(p.Provider) || !p.Gateways.Valid() || !p.Association.Valid() || !slices.Contains(pairs, p.Association) || !p.Contract.valid() || p.MaxGenerationAgeSeconds < 0 || p.MaxGenerationAgeSeconds > 2678400 {
			return core.ErrInvalid
		}
		// Until SES provides an authenticated assignment contract, never share a
		// consuming gateway pair among independent local application associations.
		g, _ := json.Marshal([]string{p.Provider, p.Gateways.Master, p.Gateways.Slave})
		if seen[p.Ref.ID] || bound[p.Association] || gateways[string(g)] {
			return core.ErrInvalid
		}
		seen[p.Ref.ID], bound[p.Association], gateways[string(g)] = true, true, true
	}
	if len(bound) != len(pairs) {
		return core.ErrInvalid
	}
	for actor, g := range c.Principals {
		if !identity(actor) || len(g.Pools) == 0 {
			return core.ErrInvalid
		}
		x := map[string]bool{}
		for _, id := range g.Pools {
			if !seen[id] || x[id] {
				return core.ErrInvalid
			}
			x[id] = true
		}
	}
	if len(c.Trust) > 64 {
		return core.ErrInvalid
	}
	trust := map[string]bool{}
	for _, t := range c.Trust {
		if t.validate() != nil || trust[t.KeyID] {
			return core.ErrInvalid
		}
		trust[t.KeyID] = true
	}
	return nil
}

func Clone[T any](v T) T { b, _ := json.Marshal(v); var out T; _ = json.Unmarshal(b, &out); return out }
