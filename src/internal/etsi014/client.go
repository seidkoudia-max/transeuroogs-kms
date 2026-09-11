package etsi014

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/upstream"
)

// Client implements only the explicitly configured synthetic 014 profile.
// Consuming requests are never automatically retried, including after redirects.
type Client struct {
	cfg  upstream.Config
	http *http.Client
}

func NewClient(c upstream.Config, tc *tls.Config) (*Client, error) {
	if c.Validate() != nil || tc == nil || tc.InsecureSkipVerify || tc.RootCAs == nil || len(tc.Certificates) != 1 || len(tc.Certificates[0].Certificate) == 0 {
		return nil, core.ErrInvalid
	}
	leaf, err := x509.ParseCertificate(tc.Certificates[0].Certificate[0])
	if err != nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != c.GatewayIdentity {
		return nil, core.ErrUnauthorized
	}
	secure := tc.Clone()
	secure.MinVersion = tls.VersionTLS13
	secure.NextProtos = []string{"http/1.1"}
	secure.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 || len(cs.PeerCertificates[0].URIs) != 1 || cs.PeerCertificates[0].URIs[0].String() != c.ServerIdentity {
			return core.ErrUnauthorized
		}
		return nil
	}
	return &Client{cfg: c, http: &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: secure, MaxIdleConnsPerHost: 1}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) request(method, peer, operation string, body any, out any) error {
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			return core.ErrInvalid
		}
	}
	defer clear(raw)
	req, err := http.NewRequestWithContext(context.Background(), method, c.cfg.URL+"/api/v1/keys/"+url.PathEscape(peer)+"/"+operation, bytes.NewReader(raw))
	if err != nil {
		return core.ErrInvalid
	}
	req.GetBody = nil
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return core.ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return core.ErrUnavailable
	}
	typ, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" {
		return core.ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	defer clear(data)
	if err != nil || len(data) > maxBody {
		return core.ErrUnavailable
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if uniqueJSON(dec, 0) != nil {
		return core.ErrUnavailable
	}
	if _, err = dec.Token(); err != io.EOF {
		return core.ErrUnavailable
	}
	// encoding/json matches struct fields case-insensitively. Restrict exact
	// standard spellings before decoding so aliases cannot replace an earlier field.
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return core.ErrUnavailable
	}
	switch out.(type) {
	case *KeyContainer:
		if len(fields) != 1 || fields["keys"] == nil {
			return core.ErrUnavailable
		}
		var keys []map[string]json.RawMessage
		if json.Unmarshal(fields["keys"], &keys) != nil || keys == nil {
			return core.ErrUnavailable
		}
		for _, k := range keys {
			if len(k) != 2 || k["key_ID"] == nil || k["key"] == nil {
				return core.ErrUnavailable
			}
		}
	case *Status:
		allowed := map[string]bool{"source_KME_ID": true, "target_KME_ID": true, "master_SAE_ID": true, "slave_SAE_ID": true, "key_size": true, "stored_key_count": true, "max_key_count": true, "max_key_per_request": true, "max_key_size": true, "min_key_size": true, "max_SAE_ID_count": true}
		for name, value := range fields {
			if !allowed[name] || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return core.ErrUnavailable
			}
		}
	default:
		return core.ErrInvalid
	}
	dec = json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(out) != nil {
		return core.ErrUnavailable
	}
	return nil
}

func validateKeys(container KeyContainer, count int, ids []core.KeyID) (out []core.Delivery, err error) {
	defer func() {
		if err != nil {
			for _, k := range out {
				clear(k.Material)
			}
			out = nil
		}
	}()
	if len(container.Keys) != count {
		return nil, core.ErrUnavailable
	}
	seen := map[core.KeyID]bool{}
	requested := map[core.KeyID]bool{}
	for _, id := range ids {
		requested[id] = true
	}
	for _, v := range container.Keys {
		id := core.KeyID(v.ID)
		material, e := base64.StdEncoding.Strict().DecodeString(v.Key)
		if e != nil || !id.Valid() || seen[id] || len(material) != core.KeyBits/8 || base64.StdEncoding.EncodeToString(material) != v.Key || (ids != nil && !requested[id]) {
			clear(material)
			return out, core.ErrUnavailable
		}
		seen[id] = true
		out = append(out, core.Delivery{ID: id, Material: material})
	}
	return out, nil
}

func (c *Client) Allocate(n int) ([]core.Delivery, error) {
	if c.cfg.Role != "master" {
		return nil, core.ErrUnauthorized
	}
	if n < 1 || n > core.MaxBatch {
		return nil, core.ErrInvalid
	}
	var out KeyContainer
	if err := c.request("POST", c.cfg.GatewaySlave, "enc_keys", map[string]int{"number": n, "size": core.KeyBits}, &out); err != nil {
		return nil, err
	}
	return validateKeys(out, n, nil)
}

func (c *Client) Retrieve(ids []core.KeyID) ([]core.Delivery, error) {
	if c.cfg.Role != "slave" {
		return nil, core.ErrUnauthorized
	}
	if len(ids) < 1 || len(ids) > core.MaxBatch {
		return nil, core.ErrInvalid
	}
	body := KeyIDs{}
	seen := map[core.KeyID]bool{}
	for _, id := range ids {
		if !id.Valid() || seen[id] {
			return nil, core.ErrInvalid
		}
		seen[id] = true
		body.IDs = append(body.IDs, KeyID{ID: string(id)})
	}
	var out KeyContainer
	if err := c.request("POST", c.cfg.GatewayMaster, "dec_keys", body, &out); err != nil {
		return nil, err
	}
	return validateKeys(out, len(ids), ids)
}

func (c *Client) Inventory() (core.Inventory, error) {
	if c.cfg.Role != "master" {
		return core.Inventory{}, core.ErrUnauthorized
	}
	var s Status
	if err := c.request("GET", c.cfg.GatewaySlave, "status", nil, &s); err != nil {
		return core.Inventory{}, err
	}
	if s.MasterSAEID != c.cfg.GatewayMaster || s.SlaveSAEID != c.cfg.GatewaySlave || s.KeySize != core.KeyBits || s.StoredKeyCount < 0 || s.MaxKeyCount < s.StoredKeyCount || s.MaxKeyCount > 100000 || s.MaxKeyPerRequest < 1 {
		return core.Inventory{}, core.ErrUnavailable
	}
	return core.Inventory{Available: s.StoredKeyCount, Capacity: s.MaxKeyCount}, nil
}
