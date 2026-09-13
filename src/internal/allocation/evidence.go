package allocation

import (
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/federation"
	"time"
)

// ProviderFacts accepts only evidence already verified at the repository input
// boundary. Controller commands cannot create or upgrade these assertions.
func ProviderFacts(f Facts, s *federation.State, id core.KeyID, setup *Setup) Facts {
	if s == nil {
		return f
	}
	if e, ok := s.Evidence[id]; ok {
		f.Source, f.Issuer, f.Evidence = e.Origin, e.Issuer, "verified_claim"
		f.Generation = &e.GeneratedAt
		if f.Expires.IsZero() || e.ExpiresAt.Before(f.Expires) {
			f.Expires = e.ExpiresAt
		}
		f.ClockUncertaintyMS = nil
		if setup != nil && setup.ClockUncertaintyMS != nil {
			n := max(*setup.ClockUncertaintyMS, int64(e.ClockUncertaintyMS))
			f.ClockUncertaintyMS = &n
		}
	}
	return f
}

// Preflight applies only request-level limits. It is used solely when a known
// evidence adapter will supply and verify every selected key's facts before
// delivery. Per-key policy is always evaluated after that consuming call.
func (s *State) Preflight(a core.Association, n int, now time.Time) string {
	if s == nil {
		return ""
	}
	if reason := s.ServiceGate(a, now); reason != "" {
		return reason
	}
	for _, app := range s.Apps {
		if app.Association == a {
			if app.Rule.Paused {
				return "paused"
			}
			if n > app.Rule.MaxKeysPerRequest {
				return "batch_limit"
			}
			return ""
		}
	}
	return "association_denied"
}
