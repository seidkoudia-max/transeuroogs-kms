// Package metapi provides the explicitly versioned, read-only metadata API.
package metapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metadata"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/security"
)

func New(store *metadata.Store, apps map[string]string, associations []core.Association, readers map[string][]core.Association) http.Handler {
	identities := map[string]string{}
	ownedApps := map[string]string{}
	ownedReaders := map[string][]core.Association{}
	for uri, sae := range apps {
		identities[uri] = uri
		ownedApps[uri] = sae
	}
	for uri, pairs := range readers {
		identities[uri] = uri
		ownedReaders[uri] = slices.Clone(pairs)
	}
	pairs := slices.Clone(associations)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		uri, ok := security.SAEIdentity(r, identities)
		if !ok {
			fail(w, 401)
			return
		}
		if r.Method != "GET" && r.Method != "POST" {
			fail(w, 405)
			return
		}
		if r.Method == "GET" && (r.ContentLength != 0 || len(r.TransferEncoding) > 0) {
			fail(w, 400)
			return
		}
		sae := ownedApps[uri]
		scope, isReader := ownedReaders[uri]
		if !isReader {
			for _, a := range pairs {
				if a.Master == sae || a.Slave == sae {
					scope = append(scope, a)
				}
			}
		}
		mux := http.NewServeMux()
		mux.HandleFunc("GET /metadata/v1/keys/{id}", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.RawQuery != "" {
				fail(w, 400)
				return
			}
			id := core.KeyID(r.PathValue("id"))
			if !id.Valid() {
				fail(w, 400)
				return
			}
			v, e := store.Key(id, uri, sae, scope)
			if errors.Is(e, core.ErrUnavailable) {
				fail(w, 404)
				return
			}
			if e != nil {
				fail(w, 503)
				return
			}
			write(w, v)
		})
		mux.HandleFunc("GET /metadata/v1/events", func(w http.ResponseWriter, r *http.Request) {
			if !isReader {
				fail(w, 403)
				return
			}
			q, e := url.ParseQuery(r.URL.RawQuery)
			if e != nil {
				fail(w, 400)
				return
			}
			var after, through uint64
			limit := metadata.MaxPage
			for k, v := range q {
				if len(v) != 1 {
					fail(w, 400)
					return
				}
				switch k {
				case "after":
					after, e = strconv.ParseUint(v[0], 10, 64)
				case "through":
					through, e = strconv.ParseUint(v[0], 10, 64)
				case "limit":
					limit, e = strconv.Atoi(v[0])
				default:
					fail(w, 400)
					return
				}
				if e != nil {
					fail(w, 400)
					return
				}
			}
			v, e := store.Page(uri, scope, after, through, limit)
			if errors.Is(e, core.ErrInvalid) {
				fail(w, 400)
				return
			}
			if e != nil {
				fail(w, 503)
				return
			}
			write(w, v)
		})
		mux.HandleFunc("POST /metadata/v1/trace", func(w http.ResponseWriter, r *http.Request) {
			if !isReader {
				fail(w, 403)
				return
			}
			if r.URL.RawQuery != "" {
				fail(w, 400)
				return
			}
			typ, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if e != nil || typ != "application/json" {
				fail(w, 415)
				return
			}
			b, e := io.ReadAll(io.LimitReader(r.Body, 8193))
			if e != nil || len(b) > 8192 {
				fail(w, 413)
				return
			}
			var q metadata.Query
			if metadata.DecodeRequest(b, &q, "incident_id", "subject", "kind", "start", "end", "clock_uncertainty_ms", "limit") != nil || q.Validate() != nil {
				fail(w, 400)
				return
			}
			v, e := store.Trace(q, scope)
			if e != nil {
				fail(w, 503)
				return
			}
			write(w, v)
		})
		mux.ServeHTTP(w, r)
	})
}

func fail(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": http.StatusText(status)})
}
func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
