package qkdrelay

import (
	"context"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/etsi020"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metadata"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/peering"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/security"
	"io"
	"net/http"
)

type Transport struct {
	*etsi020.Client
	Bridge *Bridge
	Config peering.Config
}

func (t *Transport) Send(ctx context.Context, peer string, v etsi020.Transfer) error {
	if t.Config.Peers[peer].Mode != peering.QKDRelay {
		return t.Client.Send(ctx, peer, v)
	}
	f, e := t.Bridge.Seal(peer, v)
	if e != nil {
		return e
	}
	return t.Client.SendProtected(ctx, peer, f)
}
func Handler(b *Bridge, backend etsi020.Backend, c peering.Config) http.Handler {
	fallback := etsi020.Handler(backend, c, peering.QKDRelay)
	identities := map[string]string{}
	for id, p := range c.Peers {
		if p.Mode == peering.QKDRelay {
			identities[p.Identity] = id
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != peering.Base(peering.QKDRelay) {
			fallback.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		peer, ok := security.SAEIdentity(r, identities)
		if !ok {
			w.WriteHeader(401)
			return
		}
		if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.RawPath != "" || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(400)
			return
		}
		raw, e := io.ReadAll(io.LimitReader(r.Body, 32769))
		var frame Frame
		if e != nil || len(raw) > 32768 || metadata.DecodeRequest(raw, &frame, "jwe") != nil {
			w.WriteHeader(400)
			return
		}
		if e = b.Accept(peer, frame, backend.Accept); e != nil {
			if e == core.ErrUnauthorized {
				w.WriteHeader(401)
			} else {
				w.WriteHeader(503)
			}
			return
		}
		w.WriteHeader(202)
	})
}
