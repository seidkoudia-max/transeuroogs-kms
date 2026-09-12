package sdnapi

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/storage"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestScopedManagementAnd015TTL(t *testing.T) {
	a := core.Association{Master: "A", Slave: "B"}
	setup := testallocation.Setup(a)
	setup.Config.Principals["urn:test:reader"] = allocation.Principal{Pairs: []core.Association{a}}
	r, err := storage.OpenPersistent(10, "test", &testallocation.Disk{}, nil, setup)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	handler := New(r, setup.Config, map[string]string{"urn:test:app-a": "A", "urn:test:app-b": "B"})
	request := func(actor, method, path, body, content, revision, id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", content)
		req.Header.Set("If-Match", revision)
		req.Header.Set("X-Command-ID", id)
		if actor != "" {
			uri, _ := url.Parse(actor)
			req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{uri}}}}}
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	for _, actor := range []string{"", "urn:test:app-a", "urn:test:investigator"} {
		if w := request(actor, "GET", "/management/v1/state", "", "", "", ""); w.Code != 401 {
			t.Fatal("unauthorized disclosure", w.Code)
		}
	}
	w := request(testallocation.Actor, "GET", NodePath, "", "", "", "")
	if w.Code != 200 || w.Header().Get("Content-Type") != media || bytes.Contains(w.Body.Bytes(), []byte("key_id")) {
		t.Fatal("wrong 015 response")
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("etsi-qkd-node-types:CLIENT")) {
		t.Fatal("identityref not qualified")
	}
	ttl := NodePath + "/qkd_applications/qkd_app=" + string(setup.Config.Apps[0].AppID) + "/app_qos/ttl"
	id := string(core.NewID())
	b := `{"etsi-qkd-sdn-node:ttl":30}`
	if w = request("urn:test:reader", "PUT", ttl, b, media, `"0"`, id); w.Code != 403 {
		t.Fatal("reader mutation", w.Code)
	}
	if w = request(testallocation.Actor, "PUT", ttl, b, media, "", id); w.Code != 428 {
		t.Fatal("unconditional update accepted", w.Code)
	}
	for range 2 {
		if w = request(testallocation.Actor, "PUT", ttl, b, media, `"0"`, id); w.Code != 204 {
			t.Fatal("TTL/replay", w.Code)
		}
	}
	if w = request(testallocation.Actor, "PUT", ttl, b, media, `"0"`, string(core.NewID())); w.Code != 412 {
		t.Fatal("stale update", w.Code)
	}
	if w = request(testallocation.Actor, "PUT", NodePath+"/qkd_links", `{}`, media, `"1"`, string(core.NewID())); w.Code != 405 {
		t.Fatal("unsupported physical provisioning accepted")
	}
	rule := testallocation.Rule()
	rule.Paused = true
	cmd := testallocation.Command(a, 1, rule)
	raw, _ := json.Marshal(cmd)
	if w = request(testallocation.Actor, "POST", "/management/v1/commands", string(raw), "application/json", "", ""); w.Code != 200 {
		t.Fatal("command", w.Code, w.Body.String())
	}
	bad := strings.Replace(string(raw), `"paused"`, `"Paused"`, 1)
	if w = request(testallocation.Actor, "POST", "/management/v1/commands", bad, "application/json", "", ""); w.Code != 400 {
		t.Fatal("nested case alias accepted")
	}
	bad = strings.Replace(string(raw), `"paused":true`, `"paused":true,"paused":false`, 1)
	if w = request(testallocation.Actor, "POST", "/management/v1/commands", bad, "application/json", "", ""); w.Code != 400 {
		t.Fatal("duplicate member accepted")
	}
	cmd = testallocation.Command(core.Association{Master: "X", Slave: "Y"}, 2, rule)
	raw, _ = json.Marshal(cmd)
	if w = request(testallocation.Actor, "POST", "/management/v1/commands", string(raw), "application/json", "", ""); w.Code != 403 {
		t.Fatal("scope bypass", w.Code)
	}
	if w = request(testallocation.Actor, "GET", "/management/v1/state?keys=true", "", "", "", ""); w.Code != 400 {
		t.Fatal("unknown query accepted")
	}
}
