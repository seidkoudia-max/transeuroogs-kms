package testpki

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIssuedCertificatesCarryIssuerKeyIdentifier(t *testing.T) {
	now := time.Now()
	p, err := Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(p.CA)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(ca.SubjectKeyId) == 0 {
		t.Fatal("CA lacks subject key identifier")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for name, cert := range p.Certificates {
		t.Run(name, func(t *testing.T) {
			b, _ := pem.Decode(cert.CertPEM)
			leaf, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(leaf.AuthorityKeyId, ca.SubjectKeyId) {
				t.Fatal("leaf lacks correct authority key identifier")
			}
			usage := x509.ExtKeyUsageClientAuth
			if name == "kms" {
				usage = x509.ExtKeyUsageServerAuth
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
				t.Fatal(err)
			}
			if _, err := cert.TLS(); err != nil {
				t.Fatal(err)
			}
		})
	}
	dir := t.TempDir()
	if err := p.Write(dir); err != nil {
		t.Fatal(err)
	}
	for name := range p.Certificates {
		info, err := os.Stat(filepath.Join(dir, name+".key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatal("test private key permissions too broad")
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.key.pem")); !os.IsNotExist(err) {
		t.Fatal("test CA private key persisted")
	}
}
