// Package testpki creates short-lived laboratory certificates using Go's X.509
// implementation. It must not be used as an operational certificate authority.
package testpki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Certificate struct{ CertPEM, KeyPEM []byte }

func (c Certificate) TLS() (tls.Certificate, error) { return tls.X509KeyPair(c.CertPEM, c.KeyPEM) }

type PKI struct {
	CA           []byte
	CRL          []byte
	Certificates map[string]Certificate
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return n.Add(n, big.NewInt(1))
}

func Generate(now time.Time) (PKI, error) { return GenerateRevoked(now, nil) }

func GenerateRevoked(now time.Time, revokedNames []string) (PKI, error) {
	return generate(now, revokedNames, []string{"kms", "sae-lu", "sae-gr", "unknown-sae", "controller-sae", "lu", "eagle-lu", "relay-a", "relay-b", "eagle-gr", "gr"}, "")
}

// GenerateLuxembourg creates identities for the synthetic two-link laboratory.
// These names identify simulated endpoints, not vendor or site credentials.
func GenerateLuxembourg(now time.Time) (PKI, error) {
	return generate(now, nil, []string{"windhof", "jfk-idq", "jfk-tq", "betzdorf", "sae-windhof", "sae-betzdorf", "controller-sae", "unknown-sae"}, "transeuroogs-lux")
}

func generate(now time.Time, revokedNames, names []string, namespace string) (PKI, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return PKI{}, err
	}
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "TransEuroOGS TEST CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		return PKI{}, err
	}
	// CreateCertificate generates the CA SubjectKeyId in the encoded certificate,
	// not in the template. Use the parsed CA as issuer so each leaf receives an
	// AuthorityKeyId, as required by strict X.509 validators.
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		return PKI{}, err
	}
	out := PKI{CA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Certificates: map[string]Certificate{}}
	var revoked []x509.RevocationListEntry
	for _, name := range names {
		lp, lk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return PKI{}, err
		}
		uri, _ := url.Parse("urn:transeuroogs:sae:" + name)
		leaf := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "TEST " + name}, NotBefore: now.Add(-time.Minute), NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
		if name == "kms" {
			uri, _ = url.Parse("urn:transeuroogs:kme:LU-KMS")
			leaf.URIs = []*url.URL{uri}
			leaf.DNSNames = []string{"localhost", "kms"}
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		if name != "kms" && !strings.Contains(name, "sae") {
			uri, _ = url.Parse("urn:transeuroogs:kme:" + name)
			leaf.URIs = []*url.URL{uri}
			leaf.DNSNames = []string{"localhost", name}
			if namespace != "" {
				leaf.DNSNames = append(leaf.DNSNames, name+"."+namespace+".svc.cluster.local")
			}
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		}
		for _, revokedName := range revokedNames {
			if revokedName == name {
				revoked = append(revoked, x509.RevocationListEntry{SerialNumber: leaf.SerialNumber, RevocationTime: now.Add(-time.Minute)})
			}
		}
		ld, err := x509.CreateCertificate(rand.Reader, leaf, ca, lp, priv)
		if err != nil {
			return PKI{}, err
		}
		key, err := x509.MarshalPKCS8PrivateKey(lk)
		if err != nil {
			return PKI{}, err
		}
		out.Certificates[name] = Certificate{CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ld}), KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})}
		clear(lk)
		clear(key)
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: serial(), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(12 * time.Hour), RevokedCertificateEntries: revoked}, ca, priv)
	clear(priv)
	if err != nil {
		return PKI{}, err
	}
	out.CRL = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl})
	return out, nil
}

func (p PKI) Write(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt.pem"), p.CA, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crl.pem"), p.CRL, 0600); err != nil {
		return err
	}
	for name, c := range p.Certificates {
		if err := os.WriteFile(filepath.Join(dir, name+".crt.pem"), c.CertPEM, 0600); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name+".key.pem"), c.KeyPEM, 0600); err != nil {
			return err
		}
	}
	return nil
}
