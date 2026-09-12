package config

import (
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/federation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testfederation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/upstream"
	"testing"
	"time"
)

func TestPendingSESProfileAndExplicitReviewedActivation(t *testing.T) {
	a := core.Association{Master: "A", Slave: "B"}
	f := testfederation.Config(a)
	f.Pools[0].Contract.Mode = "ses-pending"
	c := Config{KMEID: "LU", Capacity: 10, Identities: map[string]string{"urn:test:a": "A", "urn:test:b": "B"}, Associations: []core.Association{a}, LocalSAEs: []string{"A"}, Federation: f, Eagle: &upstream.Config{Profile: upstream.Profile, URL: "https://provider.invalid", ServerIdentity: f.Pools[0].Provider, GatewayIdentity: "urn:test:gateway", GatewayMaster: f.Pools[0].Gateways.Master, GatewaySlave: f.Pools[0].Gateways.Slave, Role: "master", RemoteKMEID: "remote", PKIDir: "future-input", CertificateName: "gateway", StateDir: "future-state", LifetimeSeconds: 60}}
	if e := c.Validate(); e != nil {
		t.Fatal("inspectable pending profile rejected", e)
	}
	c.Eagle.Profile = upstream.FinalProfile
	c.Eagle.Agreement = "synthetic-agreement-for-test-only"
	c.Eagle.EvidenceDir = "test-evidence"
	if e := c.Validate(); e == nil {
		t.Fatal("missing SES quantities silently accepted")
	}
	retention, age, uncertainty := 3600, 60, 0
	f.Pools[0].Contract = federation.Contract{Mode: "ses-reviewed", Agreement: c.Eagle.Agreement, APIProfile: upstream.FinalProfile, PoolSelection: "gateway-pair", FinalRelease: "paired-final-keys-only", RetentionSeconds: &retention, MaxKeyAgeSeconds: &age, ClockUncertaintyMS: &uncertainty, Recovery: "unsupported", Evidence: federation.EvidenceProfile, TrustAgreement: "synthetic-test-trust"}
	f.Pools[0].RequireEvidence = true
	if _, e := testfederation.Signing(f, time.Now()); e != nil {
		t.Fatal(e)
	}
	if e := c.Validate(); e != nil {
		t.Fatal("complete synthetic agreement fixture", e)
	}
	c.Eagle.LifetimeSeconds = 61
	if e := c.Validate(); e == nil {
		t.Fatal("local lifetime exceeds provider agreement")
	}
	c.Eagle.LifetimeSeconds = 60
	f.Pools[0].Contract.PoolSelection = "invented-provider-pool-parameter"
	if e := c.Validate(); e == nil {
		t.Fatal("unimplemented SES wire selector accepted")
	}
}

func TestPendingDeploymentTemplateReportsUnknownSESQuantities(t *testing.T) {
	c, e := Load("../../../deploy/config/federation-pending.json")
	if e != nil {
		t.Fatal(e)
	}
	s, e := federation.Open(c.Federation, nil, false, c.Associations)
	if e != nil {
		t.Fatal(e)
	}
	if s.Gate(c.Associations[0]) != "needs_SES_input" || len(c.Federation.Pools[0].Contract.Needed()) != 10 {
		t.Fatal("pending template guessed SES values or enabled allocation")
	}
}
