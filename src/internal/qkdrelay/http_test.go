package qkdrelay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/etsi020"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/peering"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testpki"
)

type httpBackend struct{ accepted atomic.Int32 }

func (b *httpBackend) Accept(string, etsi020.Transfer) error { b.accepted.Add(1); return nil }
func (*httpBackend) Acknowledge(string, []etsi020.Ack) error { return nil }
func (*httpBackend) Void(string, etsi020.Void) error         { return nil }

func TestProtectedHTTPRequiresMTLSAndNeverFallsBackToPlaintext(t *testing.T) {
	pki, err := testpki.Generate(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pki.CA)
	serverCert, _ := pki.Certificates["gr"].TLS()
	clientCert, _ := pki.Certificates["lu"].TLS()
	a, b := configs()
	a.Identity, b.Identity = "urn:transeuroogs:kme:lu", "urn:transeuroogs:kme:gr"
	p := a.Peers["b"]
	p.Identity = b.Identity
	a.Peers["b"] = p
	p = b.Peers["a"]
	p.Identity = a.Identity
	b.Peers["a"] = p
	provider := provider(t)
	right, err := Open(b, map[string]Provider{"a": provider}, 10, &testallocation.Disk{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer right.Close()
	backend := &httpBackend{}
	s := httptest.NewUnstartedServer(Handler(right, backend, b))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	s.StartTLS()
	defer s.Close()
	p = a.Peers["b"]
	p.URL = s.URL
	a.Peers["b"] = p
	left, err := Open(a, map[string]Provider{"b": provider}, 10, &testallocation.Disk{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	client, err := etsi020.NewClient(a, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	v := transfer()
	frame, err := left.Seal("b", v)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(frame)
	plain, _ := json.Marshal(v)
	for _, tc := range []struct {
		name, cert string
		body       []byte
		status     int
	}{
		{"missing certificate", "", raw, 0},
		{"application cannot relay", "sae-lu", raw, 401},
		{"different KMS", "relay-a", raw, 401},
		{"plaintext transfer", "lu", plain, 400},
		{"duplicate frame member", "lu", append(append([]byte(`{"jwe":"invalid",`), raw[1:]...), '\n'), 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
			if tc.cert != "" {
				cert, _ := pki.Certificates[tc.cert].TLS()
				tlsConfig.Certificates = []tls.Certificate{cert}
			}
			h := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}
			defer h.CloseIdleConnections()
			resp, e := h.Post(s.URL+peering.Base(peering.QKDRelay), "application/json", bytes.NewReader(tc.body))
			if tc.status == 0 {
				if e == nil {
					resp.Body.Close()
					t.Fatal("missing certificate accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatal("unexpected rejection status", resp.StatusCode)
			}
		})
	}
	if provider.retrieve != 0 || backend.accepted.Load() != 0 {
		t.Fatal("rejected HTTP request consumed a link key")
	}
	if client.Send(context.Background(), "b", v) != core.ErrUnauthorized {
		t.Fatal("plaintext client fallback")
	}
	transport := &Transport{Client: client, Bridge: left, Config: a}
	if err = transport.Probe(context.Background(), "b"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = transport.Send(context.Background(), "b", v); err != nil {
			t.Fatal(err)
		}
	}
	right.mu.Lock()
	defer right.mu.Unlock()
	if provider.alloc != 1 || provider.retrieve != 1 || backend.accepted.Load() != 1 {
		t.Fatal("HTTP retry consumed or delivered a second copy")
	}
}
