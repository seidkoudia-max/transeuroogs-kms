// Package peering defines static routing policy independently of any controller.
package peering

import (
	"errors"
	"net/url"
	"slices"
	"strings"
)

const Standard = "etsi020"
const LabRelay = "lab-relay"

type Peer struct {
	URL      string `json:"url"`
	Identity string `json:"identity"`
	Mode     string `json:"mode"`
	Incoming bool   `json:"incoming"`
}

type Config struct {
	PublicURL  string              `json:"public_url"`
	Identity   string              `json:"identity"`
	StateDir   string              `json:"state_dir"`
	LocalSAEs  []string            `json:"local_saes"`
	Peers      map[string]Peer     `json:"peers"`
	Routes     map[string][]string `json:"routes"`
	TargetKMEs map[string]string   `json:"target_kmes"`
}

func Base(mode string) string {
	if mode == LabRelay {
		return "/lab/v1/relay/keys"
	}
	return "/kmapi/v1/ext_keys"
}

func Versions(mode string) string {
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
		if id == "" || !validURL(p.URL) || !strings.HasPrefix(p.Identity, "urn:") || seen[p.Identity] || urls[p.URL] || (p.Mode != Standard && p.Mode != LabRelay) {
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
		}
	}
	return nil
}
