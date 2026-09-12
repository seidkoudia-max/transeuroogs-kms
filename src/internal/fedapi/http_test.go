package fedapi

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/federation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/storage"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testfederation"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestScopedMTLSActionsAndNoKeyDisclosure(t *testing.T) {
	a, b := core.Association{Master: "A", Slave: "B"}, core.Association{Master: "C", Slave: "D"}
	c := testfederation.Config(a, b)
	c.Principals["urn:test:observer"] = federation.Grant{Pools: []string{c.Pools[0].Ref.ID}}
	r, e := storage.OpenPersistentControlled(10, "test", &testallocation.Disk{}, nil, c)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	h := New(r, *c, map[string]string{"urn:test:app": "A"})
	request := func(actor, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Identity", testfederation.Actor)
		if actor != "" {
			uri, _ := url.Parse(actor)
			req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{uri}}}}}
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	cmd := testfederation.Command(c, 0, core.NewID(), "hold")
	raw, _ := json.Marshal(cmd)
	for _, actor := range []string{"", "urn:test:controller"} {
		if w := request(actor, "GET", "/federation/v1/state", ""); w.Code != 401 {
			t.Fatal("unverified identity accepted")
		}
	}
	for _, actor := range []string{"urn:test:app", "urn:test:observer"} {
		if w := request(actor, "POST", "/federation/v1/actions", string(raw)); w.Code != 403 {
			t.Fatal("privilege escalation", w.Code)
		}
	}
	for range 2 {
		if w := request(testfederation.Actor, "POST", "/federation/v1/actions", string(raw)); w.Code != 200 {
			t.Fatal("action replay", w.Code)
		}
	}
	w := request("urn:test:app", "GET", "/federation/v1/state", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), c.Pools[1].Ref.ID) || strings.Contains(w.Body.String(), "public_jwk") || strings.Contains(w.Body.String(), "Material") {
		t.Fatal("cross-pool or secret disclosure")
	}
	bad := strings.Replace(string(raw), `"operation":"hold"`, `"operation":"hold","operation":"release"`, 1)
	if w = request(testfederation.Actor, "POST", "/federation/v1/actions", bad); w.Code != 400 {
		t.Fatal("duplicate operation accepted")
	}
	if w = request(testfederation.Actor, "GET", "/federation/v1/state?all=true", ""); w.Code != 400 {
		t.Fatal("unexpected selector accepted")
	}
}
