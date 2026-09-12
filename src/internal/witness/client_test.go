package witness

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/security"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testpki"
)

func TestWitnessClientAndLiveCertificatePolicy(t *testing.T) {
	pki, e := testpki.Generate(time.Now())
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	if e = pki.Write(dir); e != nil {
		t.Fatal(e)
	}
	ca := filepath.Join(dir, "ca.crt.pem")
	crls := []string{filepath.Join(dir, "ca.crl.pem")}
	a, e := Open(&testallocation.Disk{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	h := LiveHandler(a, map[string][]string{"urn:transeuroogs:kme:lu": {"LU"}}, crls)
	s := httptest.NewUnstartedServer(h)
	s.TLS, e = security.ServerTLS(ca)
	if e != nil {
		t.Fatal(e)
	}
	cert, _ := pki.Certificates["gr"].TLS()
	s.TLS.Certificates = []tls.Certificate{cert}
	security.RequireCRLs(s.TLS, crls)
	s.StartTLS()
	defer s.Close()
	cfg := ClientConfig{URL: s.URL, Identity: "urn:transeuroogs:kme:gr", CAFile: ca, CertificateFile: filepath.Join(dir, "lu.crt.pem"), KeyFile: filepath.Join(dir, "lu.key.pem"), CRLFiles: crls}
	c, e := NewClient(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if f, e := c.Current("LU"); e != nil || f != (Fence{}) {
		t.Fatal("new witness", e)
	}
	f := Fence{Namespace: "LU", Generation: string(core.NewID()), Digest: strings.Repeat("1", 64), Witnessed: true}
	if e = c.Advance(Fence{}, f); e != nil {
		t.Fatal(e)
	}
	if got, e := c.Current("LU"); e != nil || got != f {
		t.Fatal("witness round trip", e)
	}
	if _, e = c.Current("GR"); e == nil {
		t.Fatal("cross-namespace client read")
	}
	cfg.Identity = "urn:transeuroogs:kme:wrong"
	wrong, e := NewClient(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer wrong.Close()
	if _, e = wrong.Current("LU"); e == nil {
		t.Fatal("wrong server accepted")
	}

	// Use an intentionally reusable connection to exercise request-time CRLs.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pki.CA)
	clientCert, _ := pki.Certificates["lu"].TLS()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}, MinVersion: tls.VersionTLS13}}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	defer client.CloseIdleConnections()
	for _, status := range []int{200, 401} {
		if status == 401 {
			if e = os.WriteFile(crls[0], []byte("unavailable CRL"), 0600); e != nil {
				t.Fatal(e)
			}
		}
		resp, e := client.Get(s.URL + "/checkpoints/LU")
		if e != nil {
			t.Fatal(e)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != status {
			t.Fatal("stale connection policy", resp.StatusCode)
		}
	}
}
