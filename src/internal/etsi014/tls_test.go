package etsi014

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/security"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testpki"
)

func TestLiveMutualTLS(t *testing.T) {
	pki, err := testpki.Generate(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := pki.Write(dir); err != nil {
		t.Fatal(err)
	}
	h, _ := testHandler(t, 5)
	s := httptest.NewUnstartedServer(h)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS, err = security.ServerTLS(filepath.Join(dir, "ca.crt.pem"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pki.Certificates["kms"].TLS()
	if err != nil {
		t.Fatal(err)
	}
	s.TLS.Certificates = []tls.Certificate{cert}
	s.StartTLS()
	defer s.Close()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pki.CA)
	untrusted, err := testpki.Generate(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, cert string
		foreign    bool
		maxVersion uint16
		status     int
	}{
		{"valid", "sae-lu", false, tls.VersionTLS13, 200},
		{"missing certificate", "", false, tls.VersionTLS13, 0},
		{"unknown SAE", "unknown-sae", false, tls.VersionTLS13, 401},
		{"untrusted certificate", "sae-lu", true, tls.VersionTLS13, 0},
		{"TLS12", "sae-lu", false, tls.VersionTLS12, 0},
		{"wrong role", "sae-gr", false, tls.VersionTLS13, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, MaxVersion: tc.maxVersion}
			if tc.cert != "" {
				source := pki
				if tc.foreign {
					source = untrusted
				}
				c, err := source.Certificates[tc.cert].TLS()
				if err != nil {
					t.Fatal(err)
				}
				cfg.Certificates = []tls.Certificate{c}
			}
			transport := &http.Transport{TLSClientConfig: cfg}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			resp, err := client.Get(s.URL + "/api/v1/keys/SAE-GR/status")
			if tc.status == 0 {
				if err == nil {
					resp.Body.Close()
					t.Fatal("forbidden TLS connection accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, expected %d", resp.StatusCode, tc.status)
			}
		})
	}
}
