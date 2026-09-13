package sdnapi

import (
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

func Test015CatalogLifecycleAndTelemetryBoundary(t *testing.T) {
	a := core.Association{Master: "A", Slave: "B"}
	cfg := testallocation.Setup(a)
	testallocation.Services(cfg)
	r, err := storage.OpenPersistent(10, "test", &testallocation.Disk{}, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	h := New(r, cfg.Config, map[string]string{"urn:test:a": "A", "urn:test:b": "B"})
	request := func(actor, method, path, body, revision, id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", media)
		req.Header.Set("If-Match", revision)
		req.Header.Set("X-Command-ID", id)
		req.Header.Set("X-After-Revision", "0")
		if strings.HasPrefix(path, "/management/") {
			req.Header.Set("Content-Type", "application/json")
		}
		uri, _ := url.Parse(actor)
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{uri}}}}}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	w := request(testallocation.Actor, "GET", NodePath, "", "", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "server_app_id") {
		t.Fatal("unregistered app advertised")
	}
	app := cfg.Config.Apps[0]
	payload := map[string]any{"etsi-qkd-sdn-node:qkd_app": []map[string]any{{"app_id": app.AppID, "app_type": "etsi-qkd-node-types:CLIENT", "server_app_id": "urn:test:a", "client_app_id": []string{"urn:test:b"}, "local_qkdn_id": cfg.Config.NodeID, "remote_qkdn_id": app.RemoteNodeID, "app_qos": map[string]any{"ttl": 60}}}}
	raw, _ := json.Marshal(payload)
	id := string(core.NewID())
	path := NodePath + "/qkd_applications"
	if w = request(testallocation.Adapter, "POST", path, string(raw), `"0"`, id); w.Code != 403 {
		t.Fatal("adapter registration")
	}
	for range 2 {
		if w = request(testallocation.Actor, "POST", path, string(raw), `"0"`, id); w.Code != 201 {
			t.Fatal("create/replay", w.Code, w.Body.String())
		}
	}
	path += "/qkd_app=" + string(app.AppID)
	if w = request(testallocation.Actor, "GET", path, "", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "etsi-qkd-node-types:ON") {
		t.Fatal("created application unreadable")
	}
	bad := strings.Replace(string(raw), `"ttl":60`, `"ttl":60,"min_bandwidth":1000`, 1)
	if w = request(testallocation.Actor, "PUT", path, bad, `"1"`, string(core.NewID())); w.Code != 400 {
		t.Fatal("unsupported QoS acknowledged")
	}
	id = string(core.NewID())
	for range 2 {
		if w = request(testallocation.Actor, "DELETE", path, "", `"1"`, id); w.Code != 204 {
			t.Fatal("delete/replay", w.Code)
		}
	}
	if w = request(testallocation.Actor, "GET", path, "", "", ""); w.Code != 404 {
		t.Fatal("deleted application advertised")
	}
	if w = request(testallocation.Actor, "GET", "/management/v1/changes", "", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "application_delete") {
		t.Fatal("missing durable event page")
	}
	link := cfg.Config.Services.Links[0]
	lraw, _ := json.Marshal(map[string]any{"etsi-qkd-sdn-node:qkd_link": []map[string]any{{"qkdl_id": link.ID, "qkdl_enable": true}}})
	if w = request(testallocation.Actor, "POST", NodePath+"/qkd_links", string(lraw), `"2"`, string(core.NewID())); w.Code != 201 {
		t.Fatal("desired link", w.Code)
	}
	if w = request(testallocation.Actor, "GET", NodePath+"/qkd_links/qkd_link="+string(link.ID), "", "", ""); w.Code != 200 || strings.Contains(w.Body.String(), "qkdl_status") {
		t.Fatal("desired state fabricated observation")
	}
	// No nested aliases, duplicates or unknown report fields survive decoding.
	enabled := true
	cmd := allocation.Command{ID: core.NewID(), ExpectedRevision: 3, Association: a, Service: &allocation.ServiceCommand{ID: link.ID, Operation: "link_update", Enabled: &enabled}}
	raw, _ = json.Marshal(cmd)
	bad = strings.Replace(string(raw), `"enabled":true`, `"enabled":true,"enabled":false`, 1)
	if w = request(testallocation.Actor, "POST", "/management/v1/commands", bad, "", ""); w.Code != 400 {
		t.Fatal("duplicate service field")
	}
}
