package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/wrapping"
)

// CreateCSR generates a new private key and PKCS#10 request for an external CA.
// It never issues certificates or overwrites an existing credential generation.
func CreateCSR(dir, identity string, dns []string, ips []net.IP) error {
	u, err := url.Parse(identity)
	if err != nil || u.Scheme != "urn" || u.Opaque == "" {
		return ErrRevoked
	}
	if err = os.Mkdir(dir, 0700); err != nil {
		return err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{}, URIs: []*url.URL{u}, DNSNames: dns, IPAddresses: ips}, k)
	if err != nil {
		return err
	}
	key, err := x509.MarshalPKCS8PrivateKey(k)
	defer clear(key)
	if err != nil {
		return err
	}
	for name, data := range map[string][]byte{"identity.key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), "identity.csr.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})} {
		f, e := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(data)
		clear(data)
		if e == nil {
			e = f.Sync()
		}
		f.Close()
		if e != nil {
			return e
		}
	}
	return nil
}
func ValidateCredential(certPath, keyPath, caPath, identity, hostname string, server bool, crls []string) error {
	key, err := wrapping.PrivateRead(keyPath, 65536)
	defer clear(key)
	if err != nil {
		return err
	}
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return ErrRevoked
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != identity {
		return ErrRevoked
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return ErrRevoked
	}
	intermediates := x509.NewCertPool()
	for _, b := range pair.Certificate[1:] {
		c, e := x509.ParseCertificate(b)
		if e != nil {
			return ErrRevoked
		}
		intermediates.AddCert(c)
	}
	usage := x509.ExtKeyUsageClientAuth
	if server {
		usage = x509.ExtKeyUsageServerAuth
		if hostname == "" {
			return ErrRevoked
		}
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: hostname, KeyUsages: []x509.ExtKeyUsage{usage}})
	if err != nil {
		return ErrRevoked
	}
	return CheckCRLs(chains, crls, time.Now())
}
