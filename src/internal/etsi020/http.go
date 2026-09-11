package etsi020

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/peering"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/security"
)

type Backend interface {
	Accept(string, Transfer) error
	Acknowledge(string, []Ack) error
	Void(string, Void) error
}

func Handler(b Backend, cfg peering.Config, mode string) http.Handler {
	identities := map[string]string{}
	for id, p := range cfg.Peers {
		if p.Mode == mode {
			identities[p.Identity] = id
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		peer, ok := security.SAEIdentity(r, identities)
		if !ok {
			failure(w, core.ErrUnauthorized)
			return
		}
		if r.URL.RawQuery != "" {
			failure(w, core.ErrInvalid)
			return
		}
		if r.URL.Path == peering.Versions(mode) && r.Method == "GET" && r.ContentLength == 0 && len(r.TransferEncoding) == 0 {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(VersionContainer{Versions: []string{"v1"}})
			return
		}
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var err error
		status := 202
		switch r.URL.Path {
		case peering.Base(mode):
			if !cfg.Peers[peer].Incoming {
				failure(w, core.ErrUnauthorized)
				return
			}
			var t Transfer
			if err = decode(w, r, &t); err == nil {
				err = t.Validate()
			}
			if err == nil && t.Callback != cfg.Peers[peer].URL+peering.Base(mode)+"/ack" {
				err = core.ErrUnauthorized
			}
			if err == nil {
				err = b.Accept(peer, t)
			}
		case peering.Base(mode) + "/ack":
			var a []Ack
			status = 200
			if err = decode(w, r, &a); err == nil {
				err = ValidateAcks(a)
			}
			if err == nil {
				err = b.Acknowledge(peer, a)
			}
		case peering.Base(mode) + "/void":
			var v Void
			if err = decode(w, r, &v); err == nil {
				err = v.Validate()
			}
			if err == nil && v.Callback != cfg.Peers[peer].URL+peering.Base(mode)+"/ack" {
				err = core.ErrUnauthorized
			}
			if err == nil {
				err = b.Void(peer, v)
			}
		default:
			w.WriteHeader(404)
			return
		}
		if err != nil {
			failure(w, err)
			return
		}
		w.WriteHeader(status)
	})
}

func failure(w http.ResponseWriter, err error) {
	status, p := 503, Problem{Message: "transfer unavailable"}
	var e Error
	switch {
	case errors.As(err, &e):
		status, p = e.Code, e.Problem
	case errors.Is(err, core.ErrInvalid), errors.Is(err, core.ErrDuplicate):
		status, p.Message = 400, "invalid request"
	case errors.Is(err, core.ErrUnauthorized):
		status, p.Message = 401, "unauthorized"
	}
	p.Type = "about:blank"
	p.Status = status
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)
}

// Reject duplicate members and case-insensitive field aliases before decoding.
// Extension payloads remain opaque JSON, but duplicate members are still invalid.
func checkJSON(d *json.Decoder, typ reflect.Type, depth int) error {
	if depth > 32 {
		return core.ErrInvalid
	}
	tok, err := d.Token()
	if err != nil {
		return core.ErrInvalid
	}
	if tok == nil {
		if typ == nil {
			return nil
		}
		return core.ErrInvalid
	}
	if typ != nil && typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			t, err := d.Token()
			if err != nil {
				return core.ErrInvalid
			}
			name, ok := t.(string)
			if !ok || seen[name] {
				return core.ErrInvalid
			}
			seen[name] = true
			var child reflect.Type
			if typ != nil && typ.Kind() == reflect.Struct {
				for i := 0; i < typ.NumField(); i++ {
					f := typ.Field(i)
					if strings.Split(f.Tag.Get("json"), ",")[0] == name {
						child = f.Type
						break
					}
				}
				if child == nil {
					return core.ErrInvalid
				}
			}
			if err := checkJSON(d, child, depth+1); err != nil {
				return err
			}
		}
	case '[':
		var child reflect.Type
		if typ != nil && typ.Kind() == reflect.Slice {
			child = typ.Elem()
		}
		for d.More() {
			if err := checkJSON(d, child, depth+1); err != nil {
				return err
			}
		}
	default:
		return core.ErrInvalid
	}
	_, err = d.Token()
	return err
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return core.ErrInvalid
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
	if err != nil {
		return core.ErrInvalid
	}
	defer clear(raw)
	if !utf8.Valid(raw) {
		return core.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err = checkJSON(d, reflect.TypeOf(v).Elem(), 0); err != nil {
		return core.ErrInvalid
	}
	if _, err = d.Token(); err != io.EOF {
		return core.ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return core.ErrInvalid
	}
	return nil
}

// Transport can be replaced by a fault-injecting implementation in recovery tests.
type Transport interface {
	Probe(context.Context, string) error
	Send(context.Context, string, Transfer) error
	Ack(context.Context, string, []Ack) error
	Void(context.Context, string, Void) error
}
type Client struct {
	peers   map[string]peering.Peer
	clients map[string]*http.Client
}

func NewClient(cfg peering.Config, tlsConfig *tls.Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if tlsConfig == nil || tlsConfig.InsecureSkipVerify || tlsConfig.RootCAs == nil || len(tlsConfig.Certificates) == 0 {
		return nil, core.ErrInvalid
	}
	c := &Client{peers: map[string]peering.Peer{}, clients: map[string]*http.Client{}}
	for id, p := range cfg.Peers {
		tc := tlsConfig.Clone()
		tc.MinVersion = tls.VersionTLS13
		tc.NextProtos = []string{"http/1.1"}
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 || len(cs.PeerCertificates[0].URIs) != 1 || cs.PeerCertificates[0].URIs[0].String() != p.Identity {
				return core.ErrUnauthorized
			}
			return nil
		}
		c.peers[id] = p
		c.clients[id] = &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: tc, MaxIdleConnsPerHost: 2}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return c, nil
}
func (c *Client) Close() {
	for _, cl := range c.clients {
		cl.CloseIdleConnections()
	}
}
func (c *Client) request(ctx context.Context, id, method, path string, body any, want int, out any) error {
	p, ok := c.peers[id]
	if !ok {
		return core.ErrUnauthorized
	}
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			return core.ErrInvalid
		}
		defer clear(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.URL+path, bytes.NewReader(raw))
	if err != nil {
		return core.ErrInvalid
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.clients[id].Do(req)
	if err != nil {
		return core.ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		return core.ErrUnavailable
	}
	if out != nil {
		if json.NewDecoder(io.LimitReader(resp.Body, 16384)).Decode(out) != nil {
			return core.ErrUnavailable
		}
	}
	return nil
}
func (c *Client) Probe(ctx context.Context, id string) error {
	var v VersionContainer
	if err := c.request(ctx, id, "GET", peering.Versions(c.peers[id].Mode), nil, 200, &v); err != nil {
		return err
	}
	if !slices.Contains(v.Versions, "v1") {
		return core.ErrUnavailable
	}
	return nil
}
func (c *Client) Send(ctx context.Context, id string, t Transfer) error {
	return c.request(ctx, id, "POST", peering.Base(c.peers[id].Mode), t, 202, nil)
}
func (c *Client) Ack(ctx context.Context, id string, a []Ack) error {
	return c.request(ctx, id, "POST", peering.Base(c.peers[id].Mode)+"/ack", a, 200, nil)
}
func (c *Client) Void(ctx context.Context, id string, v Void) error {
	return c.request(ctx, id, "POST", peering.Base(c.peers[id].Mode)+"/void", v, 202, nil)
}
