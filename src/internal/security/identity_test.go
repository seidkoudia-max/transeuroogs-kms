package security

import (
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestIdentityNeverTrustsHeadersOrUnverifiedCertificates(t *testing.T) {
	u, _ := url.Parse("urn:sae:a")
	leaf := &x509.Certificate{URIs: []*url.URL{u}}
	ids := map[string]string{u.String(): "A"}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-SAE-ID", "A")
	if _, ok := SAEIdentity(r, ids); ok {
		t.Fatal("trusted header")
	}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if _, ok := SAEIdentity(r, ids); ok {
		t.Fatal("trusted unverified certificate")
	}
	r.TLS.VerifiedChains = [][]*x509.Certificate{{leaf}}
	if id, ok := SAEIdentity(r, ids); !ok || id != "A" {
		t.Fatal("verified identity rejected")
	}
	leaf.URIs = append(leaf.URIs, u)
	if _, ok := SAEIdentity(r, ids); ok {
		t.Fatal("ambiguous identity accepted")
	}
}
