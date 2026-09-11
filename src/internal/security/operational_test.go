package security

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testpki"
)

func chain(t *testing.T, revoked bool) (tls.ConnectionState, []string) {
	t.Helper()
	names := []string{}
	if revoked {
		names = []string{"sae-lu"}
	}
	p, e := testpki.GenerateRevoked(time.Now(), names)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := pem.Decode(p.CA)
	ca, e := x509.ParseCertificate(b.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	b, _ = pem.Decode(p.Certificates["sae-lu"].CertPEM)
	leaf, e := x509.ParseCertificate(b.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "crl.pem")
	os.WriteFile(path, p.CRL, 0600)
	return tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, ca}}}, []string{path}
}
func TestRevocationExpiryAndIssuer(t *testing.T) {
	cs, files := chain(t, false)
	if CheckCRLs(cs.VerifiedChains, files, time.Now()) != nil {
		t.Fatal("valid CRL rejected")
	}
	if CheckCRLs(cs.VerifiedChains, files, time.Now().Add(13*time.Hour)) == nil {
		t.Fatal("stale CRL accepted")
	}
	revoked, revfiles := chain(t, true)
	if CheckCRLs(revoked.VerifiedChains, revfiles, time.Now()) == nil {
		t.Fatal("revocation bypass")
	}
	if CheckCRLs(cs.VerifiedChains, revfiles, time.Now()) == nil {
		t.Fatal("wrong issuer accepted")
	}
	os.WriteFile(files[0], []byte("bad replacement"), 0600)
	if CheckCRLs(cs.VerifiedChains, files, time.Now()) == nil {
		t.Fatal("invalid live replacement accepted")
	}
}

type fakeAudit struct {
	fail   string
	events []string
}

func (a *fakeAudit) Record(id, actor, op, phase string, status int) error {
	a.events = append(a.events, actor+":"+op+":"+phase)
	if a.fail == phase {
		return errors.New("offline")
	}
	return nil
}
func TestGuardAuditBeforeResponseRateLimitAndLiveCRL(t *testing.T) {
	cs, files := chain(t, false)
	id := cs.PeerCertificates[0].URIs[0].String()
	a := &fakeAudit{}
	calls := 0
	h, e := Guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.Write([]byte("synthetic-key-response")) }), []string{id}, Limits{1, 2, 1}, files, a)
	if e != nil {
		t.Fatal(e)
	}
	g := h.(*guard)
	now := time.Now()
	g.now = func() time.Time { return now }
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://kms/api/v1/keys/peer/enc_keys?private=never-audit-this", nil)
		r.TLS = &cs
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	a.fail = "intent"
	if w := request(); w.Code != 503 || calls != 0 {
		t.Fatal("audit failure reached repository")
	}
	a.fail = "result"
	if w := request(); w.Code != 503 || strings.Contains(w.Body.String(), "synthetic-key-response") || calls != 1 {
		t.Fatal("unaudited key response exposed")
	}
	a.fail = ""
	if w := request(); w.Code != 429 || calls != 1 {
		t.Fatal("rate-limit bypass")
	}
	for _, s := range a.events {
		if strings.Contains(s, "private") {
			t.Fatal("query in audit")
		}
	}
	now = now.Add(time.Second)
	if w := request(); w.Code != 200 {
		t.Fatal("rate-limit refill")
	}
	os.WriteFile(files[0], []byte("invalid"), 0600)
	now = now.Add(time.Second)
	if w := request(); w.Code != 401 || calls != 2 {
		t.Fatal("existing connection bypassed CRL replacement")
	}
}
func TestCSRAndCredentialValidation(t *testing.T) {
	d := filepath.Join(t.TempDir(), "generation-1")
	if e := CreateCSR(d, "urn:test:app", []string{"localhost"}, nil); e != nil {
		t.Fatal(e)
	}
	if e := CreateCSR(d, "urn:test:app", nil, nil); e == nil {
		t.Fatal("credential overwritten")
	}
	b, e := os.ReadFile(filepath.Join(d, "identity.csr.pem"))
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(b)
	csr, e := x509.ParseCertificateRequest(block.Bytes)
	if e != nil || csr.CheckSignature() != nil || csr.URIs[0].String() != "urn:test:app" {
		t.Fatal("bad enrollment request")
	}
	p, e := testpki.Generate(time.Now())
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	p.Write(dir)
	if e := ValidateCredential(filepath.Join(dir, "kms.crt.pem"), filepath.Join(dir, "kms.key.pem"), filepath.Join(dir, "ca.crt.pem"), "urn:transeuroogs:kme:LU-KMS", "localhost", true, []string{filepath.Join(dir, "ca.crl.pem")}); e != nil {
		t.Fatal(e)
	}
	if e := ValidateCredential(filepath.Join(dir, "kms.crt.pem"), filepath.Join(dir, "kms.key.pem"), filepath.Join(dir, "ca.crt.pem"), "urn:wrong", "localhost", true, []string{filepath.Join(dir, "ca.crl.pem")}); e == nil {
		t.Fatal("wrong issued identity accepted")
	}
}
