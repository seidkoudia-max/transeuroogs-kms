package etsi020

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/peering"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testpki"
)

type backend struct {
	accepted atomic.Int32
	acks     atomic.Int32
	voids    atomic.Int32
}

func (b *backend) Accept(string, Transfer) error   { b.accepted.Add(1); return nil }
func (b *backend) Acknowledge(string, []Ack) error { b.acks.Add(1); return nil }
func (b *backend) Void(string, Void) error         { b.voids.Add(1); return nil }
func config() peering.Config {
	return peering.Config{PublicURL: "https://gr", Identity: "urn:transeuroogs:kme:gr", StateDir: "unused", Peers: map[string]peering.Peer{"lu": {URL: "https://lu", Identity: "urn:transeuroogs:kme:lu", Mode: peering.Standard, Incoming: true}}}
}
func fixture() Transfer {
	return Transfer{Keys: []Key{{ID: core.NewID(), Value: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}}, Initiator: "SAE-LU", Targets: []string{"SAE-GR"}, Callback: "https://lu/kmapi/v1/ext_keys/ack"}
}

func request(h http.Handler, path, body, identity string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	uri, _ := url.Parse(identity)
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{uri}}}}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestWireValidationAndAuthorization(t *testing.T) {
	b := &backend{}
	h := Handler(b, config(), peering.Standard)
	tr := fixture()
	buf, _ := json.Marshal(tr)
	valid := string(buf)
	for _, tc := range []struct {
		name, body, identity string
		status               int
	}{
		{"valid", valid, "urn:transeuroogs:kme:lu", 202},
		{"SAE is not KME", valid, "urn:transeuroogs:sae:sae-lu", 401},
		{"wrong KME", valid, "urn:transeuroogs:kme:relay-a", 401},
		{"unknown field", strings.Replace(valid, `"keys":`, `"Keys":`, 1), "urn:transeuroogs:kme:lu", 400},
		{"duplicate member", strings.Replace(valid, `"initiator_sae_id":"SAE-LU"`, `"initiator_sae_id":"SAE-LU","initiator_sae_id":"SAE-LU"`, 1), "urn:transeuroogs:kme:lu", 400},
		{"null body", "null", "urn:transeuroogs:kme:lu", 400},
		{"trailing JSON", valid + "{}", "urn:transeuroogs:kme:lu", 400},
		{"callback SSRF", strings.ReplaceAll(valid, "https://lu/", "https://attacker/"), "urn:transeuroogs:kme:lu", 401},
		{"wrong callback path", strings.ReplaceAll(valid, "/ext_keys/ack", "/credentials"), "urn:transeuroogs:kme:lu", 401},
		{"mandatory extension", strings.TrimSuffix(valid, "}") + `,"extension_mandatory":{"E32473_fixture":true}}`, "urn:transeuroogs:kme:lu", 503},
		{"optional opaque extension", strings.TrimSuffix(valid, "}") + `,"extension_optional":{"E32473_fixture":{"nested":[null,1]}}}`, "urn:transeuroogs:kme:lu", 202},
		{"empty extension", strings.TrimSuffix(valid, "}") + `,"extension_optional":{}}`, "urn:transeuroogs:kme:lu", 400},
		{"nested duplicate", strings.TrimSuffix(valid, "}") + `,"extension_optional":{"E32473_fixture":{"x":1,"x":2}}}`, "urn:transeuroogs:kme:lu", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request(h, "/kmapi/v1/ext_keys", tc.body, tc.identity)
			if w.Code != tc.status {
				t.Fatalf("status %d expected %d", w.Code, tc.status)
			}
			if w.Code >= 400 {
				var p Problem
				if json.Unmarshal(w.Body.Bytes(), &p) != nil || p.Type == "" || p.Status != w.Code {
					t.Fatal("not an RFC9457 problem")
				}
			}
			if strings.Contains(w.Body.String(), tr.Keys[0].Value) {
				t.Fatal("error leaked material")
			}
		})
	}
	invalidUTF8 := strings.TrimSuffix(valid, "}") + `,"extension_optional":{"E32473_fixture":"` + string([]byte{0xff}) + `"}}`
	if request(h, "/kmapi/v1/ext_keys", invalidUTF8, "urn:transeuroogs:kme:lu").Code != 400 {
		t.Fatal("invalid UTF-8 accepted")
	}
	missingIDs := `[{"ack_status":"relayed","initiator_sae_id":"SAE-LU","target_sae_ids":["SAE-GR"]}]`
	if request(h, "/kmapi/v1/ext_keys/ack", missingIDs, "urn:transeuroogs:kme:lu").Code != 400 {
		t.Fatal("ACK missing required IDs accepted")
	}
	if b.accepted.Load() != 2 {
		t.Fatal("rejected request reached backend")
	}
	acks := []Ack{{IDs: []KeyRef{{ID: tr.Keys[0].ID}}, Status: "relayed", Initiator: tr.Initiator, Targets: tr.Targets}}
	a, _ := json.Marshal(acks)
	if w := request(h, "/kmapi/v1/ext_keys/ack", string(a), "urn:transeuroogs:kme:lu"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request(h, "/kmapi/v1/ext_keys/ack", string(a[1:len(a)-1]), "urn:transeuroogs:kme:lu"); w.Code != 400 {
		t.Fatal("ACK must be an array")
	}
	for _, confirm := range []bool{false, true} {
		v := Void{IDs: []core.KeyID{}, Initiator: tr.Initiator, Targets: tr.Targets, Callback: tr.Callback, All: confirm}
		raw, _ := json.Marshal(v)
		w := request(h, "/kmapi/v1/ext_keys/void", string(raw), "urn:transeuroogs:kme:lu")
		want := 400
		if confirm {
			want = 202
		}
		if w.Code != want {
			t.Fatal("bulk void confirmation", w.Code)
		}
	}
	tr.Callback = ""
	if err := tr.Validate(); err == nil {
		t.Fatal("unadvertised synchronous mode accepted")
	}
}

func TestRealMTLSIdentityPinningAndNoRedirect(t *testing.T) {
	pki, err := testpki.Generate(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pki.CA)
	serverCert, _ := pki.Certificates["gr"].TLS()
	clientCert, _ := pki.Certificates["lu"].TLS()
	b := &backend{}
	cfg := config()
	var redirect atomic.Bool
	h := Handler(b, cfg, peering.Standard)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirect.Load() {
			http.Redirect(w, r, "https://example.invalid/", 307)
			return
		}
		h.ServeHTTP(w, r)
	}))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	s.StartTLS()
	defer s.Close()
	cc := peering.Config{PublicURL: "https://lu", Identity: "urn:transeuroogs:kme:lu", StateDir: "unused", Peers: map[string]peering.Peer{"gr": {URL: s.URL, Identity: "urn:transeuroogs:kme:gr", Mode: peering.Standard}}}
	client, err := NewClient(cc, &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{clientCert}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Probe(context.Background(), "gr"); err != nil {
		t.Fatal(err)
	}
	if err := client.Send(context.Background(), "gr", fixture()); err != nil {
		t.Fatal(err)
	}
	redirect.Store(true)
	if client.Send(context.Background(), "gr", fixture()) == nil {
		t.Fatal("redirect followed")
	}
	redirect.Store(false)
	p := cc.Peers["gr"]
	p.Identity = "urn:transeuroogs:kme:relay-a"
	cc.Peers["gr"] = p
	wrong, err := NewClient(cc, &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{clientCert}})
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if wrong.Probe(context.Background(), "gr") == nil {
		t.Fatal("wrong server URI accepted")
	}
	for _, name := range []string{"", "sae-lu", "relay-a"} {
		tc := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
		if name != "" {
			cert, _ := pki.Certificates[name].TLS()
			tc.Certificates = []tls.Certificate{cert}
		}
		tpt := &http.Transport{TLSClientConfig: tc}
		cl := &http.Client{Transport: tpt, Timeout: time.Second}
		resp, err := cl.Get(s.URL + "/kmapi/versions")
		if name == "" {
			if err == nil {
				resp.Body.Close()
				t.Fatal("missing client certificate accepted")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 401 {
				t.Fatal("non-peer role accepted")
			}
		}
		tpt.CloseIdleConnections()
	}
}
func TestPinnedUpstreamContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "api", "etsi020", "upstream", "interop-kms_ExtraMarkup.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "300ce31c46452acda4c17542c4e124ec023e975a74ac4f1ddd8cd9f4e71951c6" {
		t.Fatal("published contract changed; review profile and vectors")
	}
	for _, path := range []string{"/kmapi/versions:", "/kmapi/v1/ext_keys:", "/kmapi/v1/ext_keys/ack:", "/kmapi/v1/ext_keys/void:"} {
		if !bytes.Contains(raw, []byte(path)) {
			t.Fatal("missing published operation")
		}
	}
}
