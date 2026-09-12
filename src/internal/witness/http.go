package witness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/security"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

type ClientConfig struct {
	URL             string   `json:"url"`
	Identity        string   `json:"server_identity"`
	CAFile          string   `json:"ca_file"`
	CertificateFile string   `json:"certificate_file"`
	KeyFile         string   `json:"key_file"`
	CRLFiles        []string `json:"crl_files"`
}

func (c ClientConfig) Validate() error {
	u, e := url.Parse(c.URL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || !strings.HasPrefix(c.Identity, "urn:") || c.CAFile == "" || c.CertificateFile == "" || c.KeyFile == "" || len(c.CRLFiles) == 0 {
		return core.ErrInvalid
	}
	return nil
}

type Client struct {
	config ClientConfig
	http   *http.Client
}

func NewClient(c ClientConfig) (*Client, error) {
	if c.Validate() != nil {
		return nil, core.ErrInvalid
	}
	cert, e := tls.LoadX509KeyPair(c.CertificateFile, c.KeyFile)
	if e != nil {
		return nil, core.ErrInvalid
	}
	ca, e := os.ReadFile(c.CAFile)
	roots := x509.NewCertPool()
	if e != nil || !roots.AppendCertsFromPEM(ca) {
		return nil, core.ErrInvalid
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert}}
	security.RequireCRLs(tc, c.CRLFiles)
	old := tc.VerifyConnection
	tc.VerifyConnection = func(cs tls.ConnectionState) error {
		if e := old(cs); e != nil {
			return e
		}
		if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 || len(cs.PeerCertificates[0].URIs) != 1 || cs.PeerCertificates[0].URIs[0].String() != c.Identity {
			return core.ErrUnauthorized
		}
		return nil
	}
	return &Client{c, &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: tc, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func tag(f Fence) string {
	b, _ := json.Marshal(f)
	h := sha256.Sum256(b)
	return `"` + hex.EncodeToString(h[:]) + `"`
}
func (c *Client) request(method, ns string, before, next Fence) (Fence, error) {
	var body []byte
	if method == "PUT" {
		body, _ = json.Marshal(next)
	}
	r, e := http.NewRequestWithContext(context.Background(), method, c.config.URL+"/checkpoints/"+url.PathEscape(ns), bytes.NewReader(body))
	if e != nil {
		return Fence{}, core.ErrInvalid
	}
	r.GetBody = nil
	r.Header.Set("Content-Type", "application/json")
	if method == "PUT" {
		r.Header.Set("If-Match", tag(before))
	}
	resp, e := c.http.Do(r)
	if e != nil {
		return Fence{}, durable.ErrState
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Fence{}, durable.ErrState
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 4097))
	var f Fence
	if e != nil || len(raw) > 4096 || json.Unmarshal(raw, &f) != nil || (f != (Fence{}) && (f.Namespace != ns || !f.Valid())) {
		return Fence{}, durable.ErrState
	}
	return f, nil
}
func (c *Client) Current(ns string) (Fence, error) { return c.request("GET", ns, Fence{}, Fence{}) }
func (c *Client) Advance(before, next Fence) error {
	f, e := c.request("PUT", next.Namespace, before, next)
	if e != nil {
		return e
	}
	if f != next {
		return durable.ErrState
	}
	return nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }

// LiveHandler rechecks current certificate policy for every request, including
// keep-alive connections established before a CRL was replaced or expired.
func LiveHandler(a Authority, grants map[string][]string, paths []string) http.Handler {
	h := Handler(a, grants)
	crls := slices.Clone(paths)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || security.CheckCRLs(r.TLS.VerifiedChains, crls, time.Now()) != nil {
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func Handler(a Authority, grants map[string][]string) http.Handler {
	ids := map[string]string{}
	owned := map[string][]string{}
	for id, nss := range grants {
		ids[id] = id
		owned[id] = slices.Clone(nss)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		id, ok := security.SAEIdentity(r, ids)
		ns, has := strings.CutPrefix(r.URL.Path, "/checkpoints/")
		if !ok {
			w.WriteHeader(401)
			return
		}
		if !has || !slices.Contains(owned[id], ns) {
			w.WriteHeader(403)
			return
		}
		if r.URL.RawQuery != "" {
			w.WriteHeader(400)
			return
		}
		current, e := a.Current(ns)
		if e != nil {
			w.WriteHeader(503)
			return
		}
		if r.Method == "PUT" {
			raw, e := io.ReadAll(io.LimitReader(r.Body, 4097))
			var next Fence
			if e != nil || len(raw) > 4096 || json.Unmarshal(raw, &next) != nil || next.Namespace != ns || !next.Valid() {
				w.WriteHeader(400)
				return
			}
			var compact bytes.Buffer
			want, _ := json.Marshal(next)
			if json.Compact(&compact, raw) != nil || !bytes.Equal(want, compact.Bytes()) {
				w.WriteHeader(400)
				return
			}
			if next != current && r.Header.Get("If-Match") != tag(current) {
				w.WriteHeader(412)
				return
			}
			if e = a.Advance(current, next); e != nil {
				w.WriteHeader(503)
				return
			}
			current = next
		} else if r.Method != "GET" || r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
			w.WriteHeader(405)
			return
		}
		w.Header().Set("ETag", tag(current))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(current)
	})
}
