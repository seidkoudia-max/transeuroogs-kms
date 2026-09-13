package testpki

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLuxembourgEndpointAndClientIdentities(t *testing.T) {
	now := time.Now()
	p, err := GenerateLuxembourg(now)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(p.CA) || len(p.Certificates) != 8 {
		t.Fatal("incomplete Luxembourg test profile")
	}
	for name, certificate := range p.Certificates {
		block, _ := pem.Decode(certificate.CertPEM)
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		client := strings.Contains(name, "sae")
		role := "kme"
		if client {
			role = "sae"
		}
		if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "urn:transeuroogs:"+role+":"+name {
			t.Fatal("wrong endpoint identity")
		}
		options := x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if _, err := leaf.Verify(options); err != nil {
			t.Fatal(err)
		}
		options.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if client {
			if _, err := leaf.Verify(options); err == nil {
				t.Fatal("application/controller credential allowed as server")
			}
			continue
		}
		options.DNSName = name + ".transeuroogs-lux.svc.cluster.local"
		if _, err := leaf.Verify(options); err != nil {
			t.Fatal(err)
		}
		options.DNSName = "other.transeuroogs-lux.svc.cluster.local"
		if _, err := leaf.Verify(options); err == nil {
			t.Fatal("certificate accepted for a different endpoint")
		}
		if leaf.NotAfter.Sub(now) > 24*time.Hour {
			t.Fatal("test certificate lifetime too long")
		}
	}
}

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

func TestServicesProfileRolesAndNamespace(t *testing.T) {
	p, err := GenerateServices(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Certificates) != 13 {
		t.Fatal("incomplete services profile")
	}
	for name, credential := range p.Certificates {
		block, _ := pem.Decode(credential.CertPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(name, "sae") {
			for _, usage := range cert.ExtKeyUsage {
				if usage == x509.ExtKeyUsageServerAuth {
					t.Fatal("client issued server authority")
				}
			}
		} else if err = cert.VerifyHostname(name + ".transeuroogs-services.svc.cluster.local"); err != nil {
			t.Fatal(err)
		}
	}
}
