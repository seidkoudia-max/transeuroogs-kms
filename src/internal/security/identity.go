package security

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
)

// SAEIdentity trusts only the verified leaf, never caller-supplied headers or CN.
func SAEIdentity(r *http.Request, identities map[string]string) (string, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", false
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if len(leaf.URIs) != 1 {
		return "", false
	}
	sae, ok := identities[leaf.URIs[0].String()]
	return sae, ok && sae != ""
}

func ServerTLS(caPath string) (*tls.Config, error) {
	data, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("no CA certificates loaded")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, nil
}
