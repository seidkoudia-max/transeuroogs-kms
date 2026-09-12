package metadata

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
)

// Signing uses RFC 7515 JWS compact serialization and RFC 7518 ES256 through
// go-jose. Only a separately provisioned P-256 PKCS#8 credential is accepted.
type Signing struct {
	signer      jose.Signer
	public      *ecdsa.PublicKey
	kid         string
	fingerprint string
}

func LoadSigning(path, kid string) (*Signing, error) {
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 16384 {
		return nil, ErrEvidence
	}
	b, e := os.ReadFile(path)
	defer clear(b)
	if e != nil {
		return nil, ErrEvidence
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrEvidence
	}
	defer clear(block.Bytes)
	k, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, ErrEvidence
	}
	p, ok := k.(*ecdsa.PrivateKey)
	if !ok || p.Curve != elliptic.P256() {
		return nil, ErrEvidence
	}
	return NewSigning(p, kid)
}

func NewSigning(k *ecdsa.PrivateKey, kid string) (*Signing, error) {
	if k == nil || k.Curve != elliptic.P256() || !name(kid) {
		return nil, ErrEvidence
	}
	s, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k}, (&jose.SignerOptions{}).WithType("transeuroogs-metadata+jws").WithHeader("kid", kid))
	if e != nil {
		return nil, ErrEvidence
	}
	der, e := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if e != nil {
		return nil, ErrEvidence
	}
	return &Signing{s, &k.PublicKey, kid, checksum(der)}, nil
}

func checksum(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }

func (s *Signing) Sign(v any) (string, error) {
	b, e := marshal(v)
	if e != nil {
		return "", ErrEvidence
	}
	o, e := s.signer.Sign(b)
	if e != nil {
		return "", ErrEvidence
	}
	return o.CompactSerialize()
}

func verify(token string, public *ecdsa.PublicKey, kid string, out any, max int) error {
	if len(token) > max || strings.Count(token, ".") != 2 || strings.TrimSpace(token) != token {
		return ErrEvidence
	}
	encoded, _, _ := strings.Cut(token, ".")
	header, e := base64.RawURLEncoding.DecodeString(encoded)
	var exact struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}
	if e != nil || DecodeRequest(header, &exact, "alg", "kid", "typ") != nil || exact.Algorithm != "ES256" || exact.KeyID != kid || exact.Type != "transeuroogs-metadata+jws" {
		return ErrEvidence
	}
	o, e := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.ES256})
	if e != nil || len(o.Signatures) != 1 {
		return ErrEvidence
	}
	h := o.Signatures[0].Protected
	if h.KeyID != kid || h.Algorithm != string(jose.ES256) || h.JSONWebKey != nil || len(h.ExtraHeaders) != 1 || h.ExtraHeaders["typ"] != "transeuroogs-metadata+jws" {
		return ErrEvidence
	}
	b, e := o.Verify(public)
	if e != nil || decode(b, out) != nil {
		return ErrEvidence
	}
	return nil
}
