// Package fedapi exposes scoped local protection operations over the existing
// mutually authenticated listener. It is a versioned project API, not ETSI 014.
package fedapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/federation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/ingest"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metadata"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/security"
)

func New(manager federation.Manager, config federation.Config, apps map[string]string) http.Handler {
	c := federation.Clone(config)
	identities := map[string]string{}
	for actor := range c.Principals {
		identities[actor] = actor
	}
	for actor := range apps {
		identities[actor] = actor
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fail := func(status int) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": http.StatusText(status)})
		}
		write := func(v any) { w.Header().Set("Content-Type", "application/json"); _ = json.NewEncoder(w).Encode(v) }
		actor, ok := security.SAEIdentity(r, identities)
		if !ok {
			fail(401)
			return
		}
		if r.URL.RawPath != "" || r.URL.RawQuery != "" || (r.Method == "GET" && (r.ContentLength != 0 || len(r.TransferEncoding) > 0)) {
			fail(400)
			return
		}
		sae := apps[actor]
		grant, operator := c.Principals[actor]
		pools := slices.Clone(grant.Pools)
		if !operator {
			for _, p := range c.Pools {
				if p.Association.Master == sae || p.Association.Slave == sae {
					pools = append(pools, p.Ref.ID)
				}
			}
		}
		if r.URL.Path == "/federation/v1/state" && r.Method == "GET" {
			v, e := manager.ProtectionView(pools, sae)
			if e != nil {
				fail(503)
				return
			}
			write(v)
			return
		}
		if r.Method != "POST" {
			fail(405)
			return
		}
		kind, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if e != nil || kind != "application/json" {
			fail(415)
			return
		}
		b, e := io.ReadAll(io.LimitReader(r.Body, 32769))
		if e != nil || len(b) > 32768 {
			fail(413)
			return
		}
		if r.URL.Path == "/federation/v1/receipts" {
			if sae == "" {
				fail(403)
				return
			}
			var receipt federation.Receipt
			if metadata.DecodeRequest(b, &receipt, "receipt_id", "session_id", "key_id", "binding", "association", "sae_id", "status", "incident_id") != nil || receipt.SAE != sae || !slices.Contains(pools, receipt.Pool.ID) {
				fail(400)
				return
			}
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(b, &fields)
			if metadata.DecodeRequest(fields["binding"], &receipt.Pool, "pool_id", "remote_pool_id", "binding_revision", "service_id", "service_epoch", "purpose") != nil || metadata.DecodeRequest(fields["association"], &receipt.Association, "master", "slave") != nil {
				fail(400)
				return
			}
			if e = manager.RecordReceipt(receipt); e != nil {
				fail(status(e))
				return
			}
			w.WriteHeader(204)
			return
		}
		if !operator {
			fail(403)
			return
		}
		switch r.URL.Path {
		case "/federation/v1/actions":
			var c federation.Command
			if metadata.DecodeRequest(b, &c, "action_id", "incident_id", "pool_id", "expected_revision", "operation", "reason") != nil {
				fail(400)
				return
			}
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(b, &fields)
			if fields["expected_revision"] == nil {
				fail(400)
				return
			}
			v, e := manager.ApplyProtection(actor, c)
			if e != nil {
				fail(status(e))
				return
			}
			write(v)
		case "/federation/v1/evidence":
			var v struct {
				Pool string `json:"pool_id"`
				JWS  string `json:"jws"`
			}
			if metadata.DecodeRequest(b, &v, "pool_id", "jws") != nil {
				fail(400)
				return
			}
			if e = manager.ImportEvidence(actor, v.Pool, v.JWS); e != nil {
				fail(status(e))
				return
			}
			w.WriteHeader(204)
		case "/federation/v1/uncertain", "/federation/v1/reconcile":
			repository, ok := manager.(interface {
				PendingRequests(string, string) ([]ingest.Pending, error)
				Reconcile(string, string, core.KeyID, core.KeyID) (federation.Reconciliation, error)
			})
			if !ok {
				fail(501)
				return
			}
			var v struct {
				Pool      string     `json:"pool_id"`
				ID        core.KeyID `json:"action_id"`
				Reference core.KeyID `json:"request_reference"`
			}
			if metadata.DecodeRequest(b, &v, "pool_id", "action_id", "request_reference") != nil {
				fail(400)
				return
			}
			if r.URL.Path == "/federation/v1/uncertain" {
				out, e := repository.PendingRequests(actor, v.Pool)
				if e != nil {
					fail(status(e))
					return
				}
				write(out)
			} else {
				out, e := repository.Reconcile(actor, v.Pool, v.ID, v.Reference)
				if e != nil {
					fail(status(e))
					return
				}
				write(out)
			}
		default:
			fail(404)
		}
	})
}
func status(e error) int {
	switch {
	case errors.Is(e, core.ErrUnauthorized):
		return 403
	case errors.Is(e, core.ErrInvalid):
		return 400
	case errors.Is(e, federation.ErrConflict):
		return 409
	default:
		return 503
	}
}
