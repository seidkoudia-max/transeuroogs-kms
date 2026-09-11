package peering

import "testing"

func TestRoutingPolicyRejectsAmbiguousOrUnsafePeers(t *testing.T) {
	base := func() Config {
		return Config{PublicURL: "https://lu", Identity: "urn:kme:lu", StateDir: "state", LocalSAEs: []string{"SAE-LU"}, Peers: map[string]Peer{"gr": {URL: "https://gr", Identity: "urn:kme:gr", Mode: Standard}}, Routes: map[string][]string{"SAE-GR": {"gr"}}}
	}
	if err := base().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"plaintext":           func(c *Config) { p := c.Peers["gr"]; p.URL = "http://gr"; c.Peers["gr"] = p },
		"credentials":         func(c *Config) { p := c.Peers["gr"]; p.URL = "https://secret@gr"; c.Peers["gr"] = p },
		"query":               func(c *Config) { p := c.Peers["gr"]; p.URL = "https://gr?redirect=other"; c.Peers["gr"] = p },
		"self peer":           func(c *Config) { p := c.Peers["gr"]; p.Identity = c.Identity; c.Peers["gr"] = p },
		"duplicate identity":  func(c *Config) { c.Peers["alias"] = c.Peers["gr"] },
		"unknown route":       func(c *Config) { c.Routes["SAE-GR"] = []string{"other"} },
		"duplicate path":      func(c *Config) { c.Routes["SAE-GR"] = []string{"gr", "gr"} },
		"local target routed": func(c *Config) { c.LocalSAEs = append(c.LocalSAEs, "SAE-GR") },
		"unknown transport":   func(c *Config) { p := c.Peers["gr"]; p.Mode = "qkd-otp"; c.Peers["gr"] = p },
	} {
		t.Run(name, func(t *testing.T) {
			c := base()
			mutate(&c)
			if c.Validate() == nil {
				t.Fatal("unsafe policy accepted")
			}
		})
	}
}
