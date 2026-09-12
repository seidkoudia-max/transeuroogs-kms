// Package peering defines static routing policy independently of any controller.
package peering

import (
	"errors"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/upstream"
	"net/url"
	"slices"
	"strings"
)

const Standard = "etsi020"
const LabRelay = "lab-relay"
const QKDRelay = "qkd-jwe-v1"

type Peer struct {
	Link     *upstream.Config `json:"link_key_source,omitempty"`
	URL      string           `json:"url"`
	Identity string           `json:"identity"`
	Mode     string           `json:"mode"`
	Incoming bool             `json:"incoming"`
}

type Config struct {
	QKDStateDir string              `json:"qkd_state_dir,omitempty"`
	PublicURL   string              `json:"public_url"`
	Identity    string              `json:"identity"`
	StateDir    string              `json:"state_dir"`
	LocalSAEs   []string            `json:"local_saes"`
	Peers       map[string]Peer     `json:"peers"`
	Routes      map[string][]string `json:"routes"`
	TargetKMEs  map[string]string   `json:"target_kmes"`
}

func Base(mode string) string {
	if mode == QKDRelay {
		return "/qkd/v1/ext_keys"
	}
	if mode == LabRelay {
		return "/lab/v1/relay/keys"
	}
	return "/kmapi/v1/ext_keys"
}

func Versions(mode string) string {
	if mode == QKDRelay {
		return "/qkd/versions"
	}
	if mode == LabRelay {
		return "/lab/versions"
	}
	return "/kmapi/versions"
}

func validURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Path == "" && !u.ForceQuery
}

func (c Config) Validate() error {
	bad := errors.New("invalid inter-KMS routing configuration")
	if !validURL(c.PublicURL) || !strings.HasPrefix(c.Identity, "urn:") || c.StateDir == "" || len(c.Peers) == 0 {
		return bad
	}
	seen := map[string]bool{c.Identity: true}
	urls := map[string]bool{c.PublicURL: true}
	for id, p := range c.Peers {
		if id == "" || !validURL(p.URL) || !strings.HasPrefix(p.Identity, "urn:") || seen[p.Identity] || urls[p.URL] || (p.Mode != Standard && p.Mode != LabRelay && p.Mode != QKDRelay) {
			return bad
		}
		if p.Mode == QKDRelay {
			if p.Link == nil || p.Link.Validate() != nil || (p.Link.Profile != upstream.Profile && p.Link.Profile != upstream.LinkProfile) || c.QKDStateDir == "" || c.QKDStateDir == c.StateDir || (p.Incoming && p.Link.Role != "slave") {
				return bad
			}
		} else if p.Link != nil {
			return bad
		}
		seen[p.Identity], urls[p.URL] = true, true
	}
	locals := map[string]bool{}
	for _, id := range c.LocalSAEs {
		if id == "" || locals[id] {
			return bad
		}
		locals[id] = true
	}
	for target, route := range c.Routes {
		if target == "" || len(route) == 0 || locals[target] {
			return bad
		}
		for i, id := range route {
			if _, ok := c.Peers[id]; !ok || slices.Contains(route[:i], id) {
				return bad
			}
			if p := c.Peers[id]; p.Mode == QKDRelay && p.Link.Role != "master" {
				return bad
			}
		}
	}
	return nil
}
