package etsi014

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testpki"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/upstream"
)

func clientFixture(t *testing.T, h http.Handler) (upstream.Config, *tls.Config) {
	t.Helper()
	p, e := testpki.Generate(time.Now())
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(p.CA)
	serverCert, _ := p.Certificates["eagle-lu"].TLS()
	gateway, _ := p.Certificates["lu"].TLS()
	s := httptest.NewUnstartedServer(h)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
	s.StartTLS()
	t.Cleanup(s.Close)
	c := upstream.Config{Profile: upstream.Profile, URL: s.URL, ServerIdentity: "urn:transeuroogs:kme:eagle-lu", GatewayIdentity: "urn:transeuroogs:kme:lu", GatewayMaster: "GW-LU", GatewaySlave: "GW-GR", Role: "master", RemoteKMEID: "GR", StateDir: "unused", PKIDir: "unused", CertificateName: "lu", LifetimeSeconds: 60}
	return c, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{gateway}}
}

func TestUpstreamClientTLSProfileAndNoRetry(t *testing.T) {
	var calls atomic.Int32
	id := core.NewID()
	c, tc := clientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/api/v1/keys/GW-GR/enc_keys" {
			t.Error("wrong upstream request")
		}
		var req KeyRequest
		if err := readJSON(w, r, &req, "number", "size"); err != nil || req.Number == nil || *req.Number != 1 || req.Size == nil || *req.Size != core.KeyBits {
			t.Error("invalid upstream allocation body")
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(KeyContainer{Keys: []KeyValue{{ID: string(id), Key: base64.StdEncoding.EncodeToString(make([]byte, 32))}}})
	}))
	client, e := NewClient(c, tc)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	keys, e := client.Allocate(1)
	if e != nil || len(keys) != 1 || keys[0].ID != id {
		t.Fatal("valid upstream delivery rejected")
	}
	clear(keys[0].Material)
	wrong := c
	wrong.ServerIdentity = "urn:wrong"
	bad, e := NewClient(wrong, tc)
	if e != nil {
		t.Fatal(e)
	}
	defer bad.Close()
	if _, e = bad.Allocate(1); e == nil {
		t.Fatal("wrong server identity accepted")
	}
	wrong = c
	wrong.GatewayIdentity = "urn:wrong"
	if bad, e = NewClient(wrong, tc); e == nil {
		bad.Close()
		t.Fatal("wrong client identity accepted")
	}
	wrong = c
	wrong.Profile = "production"
	if bad, e = NewClient(wrong, tc); e == nil {
		bad.Close()
		t.Fatal("unknown deployment profile accepted")
	}
	if calls.Load() != 1 {
		t.Fatal("identity failure reached provider")
	}
}

func TestUpstreamMalformedBatchAndLostResponse(t *testing.T) {
	for _, mode := range []string{"redirect", "lost", "duplicate JSON", "case alias", "wrong size", "wrong ID", "extra key"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			id := core.NewID()
			c, tc := clientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if mode == "redirect" {
					w.Header().Set("Location", "https://127.0.0.1:1/forbidden")
					w.WriteHeader(307)
					return
				}
				if mode == "lost" {
					conn, _, e := w.(http.Hijacker).Hijack()
					if e == nil {
						conn.Close()
					}
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if mode == "case alias" {
					_ = json.NewEncoder(w).Encode(map[string]any{"Keys": []KeyValue{{ID: string(id), Key: base64.StdEncoding.EncodeToString(make([]byte, 32))}}})
					return
				}
				if mode == "duplicate JSON" {
					_, _ = io.WriteString(w, `{"keys":[],"keys":[]}`)
					return
				}
				b := make([]byte, 32)
				returned := id
				if mode == "wrong size" {
					b = b[:16]
				}
				if mode == "wrong ID" {
					returned = core.NewID()
				}
				keys := []KeyValue{{ID: string(returned), Key: base64.StdEncoding.EncodeToString(b)}}
				if mode == "extra key" {
					keys = append(keys, keys[0])
				}
				_ = json.NewEncoder(w).Encode(KeyContainer{Keys: keys})
			}))
			c.Role = "slave"
			client, e := NewClient(c, tc)
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			if _, e = client.Retrieve([]core.KeyID{id}); e == nil {
				t.Fatal("invalid consuming response accepted")
			}
			if calls.Load() != 1 {
				t.Fatal("consuming request retried")
			}
		})
	}
}
