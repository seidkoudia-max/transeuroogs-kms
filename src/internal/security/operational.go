package security

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
)

var ErrRevoked = errors.New("certificate policy rejected")

// CheckCRLs re-reads full issuer CRLs so revocation also applies to existing
// HTTP connections. Every non-root certificate needs a current signed CRL.
// Delta/indirect CRLs are deliberately unsupported and fail closed.
func CheckCRLs(chains [][]*x509.Certificate, paths []string, now time.Time) error {
	if len(paths) == 0 || len(chains) == 0 {
		return ErrRevoked
	}
	var lists []*x509.RevocationList
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil || len(b) > 4<<20 {
			return ErrRevoked
		}
		for len(bytes.TrimSpace(b)) > 0 {
			block, rest := pem.Decode(b)
			if block == nil || block.Type != "X509 CRL" {
				return ErrRevoked
			}
			b = rest
			list, err := x509.ParseRevocationList(block.Bytes)
			if err != nil || list.NextUpdate.IsZero() || now.Before(list.ThisUpdate) || !now.Before(list.NextUpdate) {
				return ErrRevoked
			}
			for _, ext := range list.Extensions {
				if ext.Critical || ext.Id.String() == "2.5.29.27" || ext.Id.String() == "2.5.29.28" {
					return ErrRevoked
				}
			}
			lists = append(lists, list)
		}
	}
	for _, chain := range chains {
		valid := len(chain) > 1
		for i, cert := range chain {
			if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
				valid = false
				break
			}
			if i == len(chain)-1 {
				continue
			}
			issuer := chain[i+1]
			matched := false
			for _, list := range lists {
				if !bytes.Equal(list.RawIssuer, issuer.RawSubject) || list.CheckSignatureFrom(issuer) != nil {
					continue
				}
				matched = true
				for _, revoked := range list.RevokedCertificateEntries {
					if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
						return ErrRevoked
					}
				}
			}
			if !matched {
				valid = false
				break
			}
		}
		if valid {
			return nil
		}
	}
	return ErrRevoked
}
func RequireCRLs(c *tls.Config, paths []string) {
	previous := c.VerifyConnection
	c.SessionTicketsDisabled = true
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		if previous != nil {
			if err := previous(cs); err != nil {
				return err
			}
		}
		return CheckCRLs(cs.VerifiedChains, paths, time.Now())
	}
}

type Audit interface {
	Record(requestID, actor, operation, phase string, status int) error
}
type Limits struct {
	RequestsPerSecond int `json:"requests_per_second"`
	Burst             int `json:"burst"`
	MaxConcurrent     int `json:"max_concurrent"`
}

func (l Limits) Valid() bool {
	return l.RequestsPerSecond > 0 && l.RequestsPerSecond <= 10000 && l.Burst > 0 && l.Burst <= 10000 && l.MaxConcurrent > 0 && l.MaxConcurrent <= 256
}

type bucket struct {
	tokens float64
	last   time.Time
}
type guard struct {
	mu         sync.Mutex
	buckets    map[string]*bucket
	limit      Limits
	slots      chan struct{}
	identities map[string]bool
	audit      Audit
	crls       []string
	next       http.Handler
	now        func() time.Time
}

func Guard(next http.Handler, identities []string, limits Limits, crls []string, audit Audit) (http.Handler, error) {
	if next == nil || audit == nil || !limits.Valid() || len(crls) == 0 || len(identities) == 0 {
		return nil, core.ErrInvalid
	}
	g := &guard{buckets: map[string]*bucket{}, identities: map[string]bool{}, limit: limits, slots: make(chan struct{}, limits.MaxConcurrent), audit: audit, crls: crls, next: next, now: time.Now}
	for _, id := range identities {
		if id == "" || len(id) > 256 {
			return nil, core.ErrInvalid
		}
		g.identities[id] = true
	}
	return g, nil
}
func (g *guard) allow(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	b := g.buckets[id]
	if b == nil {
		b = &bucket{float64(g.limit.Burst), now}
		g.buckets[id] = b
	}
	b.tokens = min(float64(g.limit.Burst), b.tokens+now.Sub(b.last).Seconds()*float64(g.limit.RequestsPerSecond))
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type response struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	overflow bool
}

func (r *response) Header() http.Header { return r.header }
func (r *response) WriteHeader(n int) {
	if r.status == 0 {
		r.status = n
	}
}
func (r *response) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = 200
	}
	if r.body.Len()+len(b) > 128<<10 {
		r.overflow = true
		return 0, core.ErrCapacity
	}
	return r.body.Write(b)
}
func operation(r *http.Request) string {
	// Never audit a caller-provided path/query, which may contain key material.
	if strings.HasPrefix(r.URL.Path, "/management/v1/") {
		return "allocation_management"
	}
	if strings.HasPrefix(r.URL.Path, "/restconf/") {
		return "sdn_agent"
	}
	if strings.HasPrefix(r.URL.Path, "/metadata/v1/keys/") {
		return "metadata_key"
	}
	if r.URL.Path == "/metadata/v1/events" {
		return "metadata_events"
	}
	if r.URL.Path == "/metadata/v1/trace" {
		return "metadata_trace"
	}
	for _, op := range []string{"status", "enc_keys", "dec_keys", "versions", "ext_keys", "ack", "void"} {
		if strings.HasSuffix(r.URL.Path, "/"+op) {
			return op
		}
	}
	return "unknown"
}
func (g *guard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor := ""
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.PeerCertificates) > 0 && len(r.TLS.PeerCertificates[0].URIs) == 1 {
		actor = r.TLS.PeerCertificates[0].URIs[0].String()
	}
	if !g.identities[actor] || CheckCRLs(r.TLS.VerifiedChains, g.crls, g.now()) != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	if !g.allow(actor) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "request limit reached", 429)
		return
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		http.Error(w, "busy", 503)
		return
	}
	id, op := string(core.NewID()), operation(r)
	if g.audit.Record(id, actor, op, "intent", 0) != nil {
		http.Error(w, "audit unavailable", 503)
		return
	}
	b := &response{header: http.Header{}}
	defer func() { clear(b.body.Bytes()) }()
	g.next.ServeHTTP(b, r)
	if CheckCRLs(r.TLS.VerifiedChains, g.crls, g.now()) != nil {
		clear(b.body.Bytes())
		b.body.Reset()
		b.body.WriteString("unauthorized\n")
		b.status = 401
	}
	if b.status == 0 {
		b.status = 200
	}
	if b.overflow {
		b.status = 503
	}
	if g.audit.Record(id, actor, op, "result", b.status) != nil || b.overflow {
		http.Error(w, "audit unavailable", 503)
		return
	}
	for k, v := range b.header {
		w.Header()[k] = v
	}
	w.WriteHeader(b.status)
	_, _ = w.Write(b.body.Bytes())
}
