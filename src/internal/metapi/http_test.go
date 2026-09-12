package metapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metadata"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/storage"
)

type sink struct{}

func (sink) Save([]byte) error { return nil }
func (sink) Close()            {}

func TestMetadataAuthorizationScopeAndStrictInputs(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sign, e := metadata.NewSigning(k, "test")
	if e != nil {
		t.Fatal(e)
	}
	c := metadata.Config{Domain: "test", Issuer: "urn:test:kms", Namespace: "test", CredentialID: "test", SigningKeyFile: "fixture", MaxEvents: 100}
	h, raw, e := metadata.Open(c, sign, sink{}, nil, storage.ProjectMetadata, nil)
	if e != nil {
		t.Fatal(e)
	}
	r, e := storage.OpenPersistent(100, "test", h, raw)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	ab, cd := core.Association{Master: "A", Slave: "B"}, core.Association{Master: "C", Slave: "D"}
	ids := []core.KeyID{core.NewID(), core.NewID()}
	for i, a := range []core.Association{ab, cd} {
		if e := r.StoreKey(core.Key{ID: ids[i], Association: a, Material: bytes.Repeat([]byte{7}, 32), Source: "synthetic-qkd", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); e != nil {
			t.Fatal(e)
		}
	}
	handler := New(h, map[string]string{"urn:test:a": "A", "urn:test:c": "C"}, []core.Association{ab, cd}, map[string][]core.Association{"urn:test:auditor": {ab}})
	call := func(method, path, body, uri string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if uri != "" {
			u, _ := url.Parse(uri)
			req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u}}}}}
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	for _, test := range []struct {
		method, path, body, uri string
		status                  int
	}{
		{"GET", "/metadata/v1/keys/" + string(ids[0]), "", "urn:test:a", 200},
		{"GET", "/metadata/v1/keys/" + string(ids[1]), "", "urn:test:a", 404},
		{"GET", "/metadata/v1/keys/" + string(ids[1]), "", "urn:test:auditor", 404},
		{"GET", "/metadata/v1/events", "", "urn:test:a", 403},
		{"GET", "/metadata/v1/events", "", "", 401},
		{"HEAD", "/metadata/v1/events", "", "urn:test:auditor", 405},
		{"GET", "/metadata/v1/events?limit=1&limit=2", "", "urn:test:auditor", 400},
		{"GET", "/metadata/v1/events?after=%xx", "", "urn:test:auditor", 400},
		{"GET", "/metadata/v1/events?limit=999", "", "urn:test:auditor", 400},
		{"GET", "/metadata/v1/events", "{}", "urn:test:auditor", 400},
		{"POST", "/metadata/v1/trace", "{}", "urn:test:a", 403},
		{"POST", "/metadata/v1/trace", `{"subject":"x","subject":"y"}`, "urn:test:auditor", 400},
		{"POST", "/metadata/v1/trace", `{"Subject":"x"}`, "urn:test:auditor", 400},
		{"POST", "/metadata/v1/trace", strings.Repeat("x", 8193), "urn:test:auditor", 413},
	} {
		w := call(test.method, test.path, test.body, test.uri)
		if w.Code != test.status {
			t.Fatalf("%s %s: got %d want %d", test.method, test.path, w.Code, test.status)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cache enabled")
		}
	}
	w := call("GET", "/metadata/v1/events", "", "urn:test:auditor")
	if w.Code != 200 || strings.Contains(w.Body.String(), string(ids[1])) {
		t.Fatal("cross-association export")
	}
	w = call("GET", "/metadata/v1/keys/"+string(ids[0]), "", "urn:test:a")
	for _, secret := range []string{"holding_material", "next_peer", "upstream", "master_state", "slave_state"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("excessive application view")
		}
	}
	// An unverified leaf plus a spoofed caller header has no authority.
	req := httptest.NewRequest(http.MethodGet, "/metadata/v1/events", nil)
	req.Header.Set("X-SAE-ID", "urn:test:auditor")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatal("trusted unverified identity")
	}
}
