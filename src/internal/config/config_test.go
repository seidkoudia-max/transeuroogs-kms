package config

import (
	"encoding/json"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metadata"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/peering"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/upstream"
	"os"
	"path/filepath"
	"testing"
)

func TestControllerRequiresIndependentScopedIdentityAndDurableMetadata(t *testing.T) {
	a := core.Association{Master: "A", Slave: "B"}
	policy := testallocation.Setup(a)
	base := Config{KMEID: "test", Capacity: 10, Identities: map[string]string{"urn:test:app-a": "A", "urn:test:app-b": "B"}, Associations: []core.Association{a}, SDN: &policy.Config,
		Metadata: &metadata.Config{Domain: "test", Issuer: "urn:test:kms", Namespace: "test", CredentialID: "test", SigningKeyFile: "unused", StateDir: "state", MaxEvents: 100, Readers: map[string][]core.Association{"urn:test:investigator": {a}}}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Metadata = nil },
		func(c *Config) { c.Metadata.StateDir = "" },
		func(c *Config) { c.SDN.Principals["urn:test:app-a"] = c.SDN.Principals[testallocation.Actor] },
		func(c *Config) { c.SDN.Principals["urn:test:investigator"] = c.SDN.Principals[testallocation.Actor] },
		func(c *Config) { c.SDN.Apps[0].Association.Slave = "OTHER" },
		func(c *Config) {
			c.SDN.Principals[testallocation.Actor] = allocation.Principal{Pairs: []core.Association{a}, Routes: true}
		},
	} {
		c := allocation.Clone(base)
		mutate(&c)
		if c.Validate() == nil {
			t.Fatal("invalid controller configuration accepted")
		}
	}
}

func TestConfigurationValidation(t *testing.T) {
	valid := `{"kme_id":"LU-KMS","capacity":10,"identities":{"urn:a":"A","urn:b":"B"},"associations":[{"master":"A","slave":"B"}]}`
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"valid", valid, true},
		{"unknown field", `{"bogus":true}`, false},
		{"empty", `{}`, false},
		{"trailing data", valid + `{}`, false},
		{"ambiguous identity", `{"kme_id":"LU-KMS","capacity":10,"identities":{"urn:a":"A","urn:a2":"A"},"associations":[{"master":"A","slave":"B"}]}`, false},
		{"unknown SAE", `{"kme_id":"LU-KMS","capacity":10,"identities":{"urn:a":"A"},"associations":[{"master":"A","slave":"B"}]}`, false},
		{"duplicate association", `{"kme_id":"LU-KMS","capacity":10,"identities":{"urn:a":"A","urn:b":"B"},"associations":[{"master":"A","slave":"B"},{"master":"A","slave":"B"}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}

func TestSegmentedProfileRoleAndIdentityValidation(t *testing.T) {
	base := Config{KMEID: "LU", Capacity: 10, Identities: map[string]string{"urn:app:lu": "A", "urn:app:gr": "B"}, LocalSAEs: []string{"A"}, Associations: []core.Association{{Master: "A", Slave: "B"}}, Eagle: &upstream.Config{Profile: upstream.Profile, URL: "https://localhost:8443", ServerIdentity: "urn:ses:lu", GatewayIdentity: "urn:gw:lu", GatewayMaster: "GW-A", GatewaySlave: "GW-B", Role: "master", RemoteKMEID: "GR", StateDir: "state", PKIDir: "pki", CertificateName: "lu", LifetimeSeconds: 60}}
	for _, tc := range []struct {
		name   string
		valid  bool
		change func(*Config)
	}{
		{"master", true, func(*Config) {}},
		{"slave", true, func(c *Config) { c.Eagle.Role = "slave"; c.LocalSAEs = []string{"B"} }},
		{"wrong local role", false, func(c *Config) { c.LocalSAEs = []string{"B"} }},
		{"both local identities", false, func(c *Config) { c.LocalSAEs = []string{"A", "B"} }},
		{"no local identity", false, func(c *Config) { c.LocalSAEs = nil }},
		{"unknown profile", false, func(c *Config) { c.Eagle.Profile = "ses-production" }},
		{"plaintext", false, func(c *Config) { c.Eagle.URL = "http://localhost:8443" }},
		{"no role", false, func(c *Config) { c.Eagle.Role = "" }},
		{"same gateway", false, func(c *Config) { c.Eagle.GatewaySlave = c.Eagle.GatewayMaster }},
		{"missing expiry", false, func(c *Config) { c.Eagle.LifetimeSeconds = 0 }},
		{"credential traversal", false, func(c *Config) { c.Eagle.CertificateName = "../lu" }},
		{"mixed relay", false, func(c *Config) { c.InterKMS = &peering.Config{} }},
		{"multiple downstream pairs", false, func(c *Config) { c.Associations = append(c.Associations, core.Association{Master: "B", Slave: "A"}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := json.Marshal(base)
			var c Config
			_ = json.Unmarshal(data, &c)
			tc.change(&c)
			if (c.Validate() == nil) != tc.valid {
				t.Fatal("unexpected profile validation outcome")
			}
		})
	}
}

func TestMetadataRequiresDurabilityAndSeparateScopedInvestigators(t *testing.T) {
	pair := core.Association{Master: "A", Slave: "B"}
	base := Config{KMEID: "LU", Capacity: 10, Identities: map[string]string{"urn:app:a": "A", "urn:app:b": "B"}, Associations: []core.Association{pair},
		Metadata: &metadata.Config{Domain: "lab", Issuer: "urn:node:lu", Namespace: "lab-pair", CredentialID: "v1", SigningKeyFile: "outside-git.pem", StateDir: "private-state", MaxEvents: 100, Readers: map[string][]core.Association{"urn:investigator:lab": {pair}}}}
	for _, tc := range []struct {
		name   string
		valid  bool
		change func(*Config)
	}{
		{"valid", true, func(*Config) {}},
		{"missing durable state", false, func(c *Config) { c.Metadata.StateDir = "" }},
		{"application as investigator", false, func(c *Config) { c.Metadata.Readers["urn:app:a"] = []core.Association{pair} }},
		{"unknown pair", false, func(c *Config) {
			c.Metadata.Readers["urn:investigator:lab"] = []core.Association{{Master: "A", Slave: "C"}}
		}},
		{"invalid event bound", false, func(c *Config) { c.Metadata.MaxEvents = 0 }},
		{"unknown clock", true, func(c *Config) { c.Metadata.ClockUncertaintyMS = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(base)
			var c Config
			_ = json.Unmarshal(b, &c)
			tc.change(&c)
			if (c.Validate() == nil) != tc.valid {
				t.Fatal("incorrect metadata configuration acceptance")
			}
		})
	}
}
