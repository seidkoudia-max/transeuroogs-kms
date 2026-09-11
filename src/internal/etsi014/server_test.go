package etsi014

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/config"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/storage"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/synthetic"
)

func testConfig() config.Config {
	return config.Config{KMEID: "LU-KMS", Capacity: 10000, Identities: map[string]string{"urn:transeuroogs:sae:sae-lu": "SAE-LU", "urn:transeuroogs:sae:sae-gr": "SAE-GR"}, Associations: []core.Association{{Master: "SAE-LU", Slave: "SAE-GR"}}}
}

func testHandler(t *testing.T, count int) (http.Handler, *storage.Memory) {
	t.Helper()
	repo, err := storage.NewMemory(10000, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := testConfig()
	if err := synthetic.Seed(repo, c.Associations[0], count, time.Now(), time.Hour); err != nil {
		t.Fatal(err)
	}
	h, err := New(repo, c)
	if err != nil {
		t.Fatal(err)
	}
	return h, repo
}

// Unit requests supply a verified-chain fixture. tls_test.go tests real handshakes.
func request(t *testing.T, h http.Handler, method, path, body, identity string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if identity != "" {
		uri, err := url.Parse(identity)
		if err != nil {
			t.Fatal(err)
		}
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{uri}}}}}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

const lu = "urn:transeuroogs:sae:sae-lu"
const gr = "urn:transeuroogs:sae:sae-gr"
const encPath = "/api/v1/keys/SAE-GR/enc_keys"
const decPath = "/api/v1/keys/SAE-LU/dec_keys"

func Test014StatusAndMatchingDelivery(t *testing.T) {
	h, repo := testHandler(t, 3)
	w := request(t, h, "GET", "/api/v1/keys/SAE-GR/status", "", lu)
	var status Status
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || status.StoredKeyCount != 3 || status.MasterSAEID != "SAE-LU" || status.TargetKMEID != "LU-KMS" || status.MaxSAEIDCount != 0 || status.KeySize != 256 {
		t.Fatal("incorrect status")
	}
	for _, method := range []string{"GET", "POST"} {
		w = request(t, h, method, encPath, "", lu)
		var master KeyContainer
		if err := json.Unmarshal(w.Body.Bytes(), &master); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || len(master.Keys) != 1 {
			t.Fatal("master delivery failed")
		}
		key := master.Keys[0]
		material, err := base64.StdEncoding.DecodeString(key.Key)
		if err != nil || len(material) != 32 || !core.KeyID(key.ID).Valid() {
			t.Fatal("invalid delivery format")
		}
		w = request(t, h, "GET", decPath+"?key_ID="+key.ID, "", gr)
		var slave KeyContainer
		if err := json.Unmarshal(w.Body.Bytes(), &slave); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || len(slave.Keys) != 1 || slave.Keys[0] != key {
			t.Fatal("slave mismatch")
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cacheable key response")
		}
		w = request(t, h, "GET", decPath+"?key_ID="+key.ID, "", gr)
		if w.Code != 503 {
			t.Fatal("replay accepted")
		}
	}
	if repo.Inventory(testConfig().Associations[0]).Available != 1 {
		t.Fatal("inventory mismatch")
	}
}

func Test014ValidationDoesNotAllocate(t *testing.T) {
	cases := []struct {
		name, method, path, body, identity string
		status                             int
	}{
		{"zero", "POST", encPath, `{"number":0}`, lu, 400},
		{"negative", "POST", encPath, `{"number":-1}`, lu, 400},
		{"over batch", "GET", encPath + "?number=129", "", lu, 400},
		{"unsupported size", "POST", encPath, `{"size":512}`, lu, 400},
		{"fraction", "POST", encPath, `{"number":1.5}`, lu, 400},
		{"nonbyte size", "GET", encPath + "?size=257", "", lu, 400},
		{"query duplicate", "GET", encPath + "?number=1&number=2", "", lu, 400},
		{"query unknown", "GET", encPath + "?foo=bar", "", lu, 400},
		{"query empty", "GET", encPath + "?number=", "", lu, 400},
		{"query malformed", "GET", encPath + "?number=%zz", "", lu, 400},
		{"json duplicate", "POST", encPath, `{"number":1,"number":2}`, lu, 400},
		{"json casing", "POST", encPath, `{"Number":1}`, lu, 400},
		{"json unknown", "POST", encPath, `{"foo":1}`, lu, 400},
		{"json trailing", "POST", encPath, `{} {}`, lu, 400},
		{"json array", "POST", encPath, `[]`, lu, 400},
		{"json null", "POST", encPath, `null`, lu, 400},
		{"null number", "POST", encPath, `{"number":null}`, lu, 400},
		{"malformed", "POST", encPath, `{"`, lu, 400},
		{"mandatory", "POST", encPath, `{"extension_mandatory":[{"vendor_x":true}]}`, lu, 400},
		{"null optional extension", "POST", encPath, `{"extension_optional":[null]}`, lu, 400},
		{"multicast", "POST", encPath, `{"additional_slave_SAE_IDs":["SAE-X"]}`, lu, 400},
		{"oversized", "POST", encPath, strings.Repeat(" ", maxBody+1), lu, 413},
		{"post query", "POST", encPath + "?number=1", `{}`, lu, 400},
		{"GET body", "GET", encPath, `{}`, lu, 400},
		{"no cert", "GET", encPath, "", "", 401},
		{"unknown cert", "GET", encPath, "", "urn:unknown", 401},
		{"wrong role", "GET", encPath, "", gr, 401},
		{"wrong target", "GET", "/api/v1/keys/OTHER/enc_keys", "", lu, 401},
		{"empty dec", "POST", decPath, `{"key_IDs":[]}`, gr, 400},
		{"missing dec ID", "GET", decPath, "", gr, 400},
		{"invalid dec ID", "GET", decPath + "?key_ID=bad", "", gr, 400},
		{"head", "HEAD", encPath, "", lu, 405},
		{"delete", "DELETE", encPath, "", lu, 405},
		{"exhaustion", "GET", encPath + "?number=11", "", lu, 503},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, repo := testHandler(t, 10)
			w := request(t, h, tc.method, tc.path, tc.body, tc.identity)
			if w.Code != tc.status {
				t.Fatalf("status %d, expected %d", w.Code, tc.status)
			}
			if repo.Inventory(testConfig().Associations[0]).Available != 10 {
				t.Fatal("invalid request allocated material")
			}
		})
	}
}

func Test014BatchAndOptionalExtensions(t *testing.T) {
	h, _ := testHandler(t, 2)
	w := request(t, h, "POST", encPath, `{"number":2,"extension_optional":[{"vendor_test":true}]}`, lu)
	var master KeyContainer
	if err := json.Unmarshal(w.Body.Bytes(), &master); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(master.Keys) != 2 {
		t.Fatal("batch failed")
	}
	body, _ := json.Marshal(KeyIDs{IDs: []KeyID{{ID: master.Keys[0].ID}, {ID: master.Keys[1].ID}}})
	w = request(t, h, "POST", decPath, string(body), gr)
	var slave KeyContainer
	if err := json.Unmarshal(w.Body.Bytes(), &slave); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(slave.Keys) != 2 || slave.Keys[0] != master.Keys[0] || slave.Keys[1] != master.Keys[1] {
		t.Fatal("batch mismatch")
	}
	if request(t, h, "GET", encPath, "", lu).Code != 503 {
		t.Fatal("exhausted pool delivered")
	}
}

type failedWriter struct{ header http.Header }

func (w failedWriter) Header() http.Header       { return w.header }
func (w failedWriter) WriteHeader(int)           {}
func (w failedWriter) Write([]byte) (int, error) { return 0, http.ErrAbortHandler }

func TestLostResponseBurnsDelivery(t *testing.T) {
	h, repo := testHandler(t, 1)
	r := httptest.NewRequest("GET", encPath, nil)
	uri, _ := url.Parse(lu)
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{uri}}}}}
	h.ServeHTTP(failedWriter{header: make(http.Header)}, r)
	if repo.Inventory(testConfig().Associations[0]).Available != 0 {
		t.Fatal("lost response restored key")
	}
	if request(t, h, "GET", encPath, "", lu).Code != 503 {
		t.Fatal("key redelivered")
	}
}

func TestJSONContentType(t *testing.T) {
	h, repo := testHandler(t, 1)
	r := httptest.NewRequest("POST", encPath, bytes.NewBufferString(`{}`))
	u, _ := url.Parse(lu)
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u}}}}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 415 || repo.Inventory(testConfig().Associations[0]).Available != 1 {
		t.Fatal("non-JSON body accepted")
	}
}
