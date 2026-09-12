package testfederation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/federation"
	"time"
)

const Actor = "urn:test:protection-operator"

func Config(pairs ...core.Association) *federation.Config {
	c := &federation.Config{Profile: federation.Profile, MaxActions: 1000, Principals: map[string]federation.Grant{}}
	var ids []string
	for n, a := range pairs {
		id := fmt.Sprintf("LU/OGS/to-%d/final", n)
		c.Pools = append(c.Pools, federation.Pool{Ref: core.PoolRef{ID: id, Revision: 1, RemoteID: fmt.Sprintf("REMOTE/%d/to-LU/final", n), Service: fmt.Sprintf("synthetic-final-%d", n), Purpose: "application-tls", ServiceEpoch: "lab-1"}, Domain: "LU", OGS: "Windhof", RemoteDomain: fmt.Sprintf("REMOTE-%d", n), RemoteOGS: fmt.Sprintf("OGS-%d", n), Association: a, Provider: "urn:test:provider", Gateways: core.Association{Master: fmt.Sprintf("GW-LU-%d", n), Slave: fmt.Sprintf("GW-REMOTE-%d", n)}, Mapping: "synthetic-provisioning", Contract: federation.Contract{Mode: "synthetic"}})
		ids = append(ids, id)
	}
	c.Principals[Actor] = federation.Grant{Pools: ids, Operate: true}
	return c
}

func Signing(c *federation.Config, now time.Time) (*ecdsa.PrivateKey, error) {
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	j, e := json.Marshal(jose.JSONWebKey{Key: &k.PublicKey, Algorithm: "ES256", Use: "sig"})
	if e != nil {
		return nil, e
	}
	var services []string
	for _, p := range c.Pools {
		services = append(services, p.Ref.Service)
	}
	c.Trust = []federation.Trust{{Issuer: c.Pools[0].Provider, KeyID: "synthetic-provider-1", PublicJWK: j, Services: services, NotBefore: now.Add(-time.Hour).UTC().Format(time.RFC3339), NotAfter: now.Add(2 * time.Hour).UTC().Format(time.RFC3339)}}
	return k, nil
}
func Evidence(p federation.Pool, id core.KeyID, now time.Time) federation.Evidence {
	return federation.Evidence{Profile: federation.EvidenceProfile, ID: core.NewID(), Key: id, Issuer: p.Provider, Pool: p.Ref, Gateways: p.Gateways, Association: p.Association, Origin: "synthetic", Kind: "final", Ready: true, GeneratedAt: now.Add(-time.Second), IssuedAt: now, ExpiresAt: now.Add(time.Minute), SigningKey: "synthetic-provider-1"}
}
func Command(c *federation.Config, revision uint64, incident core.KeyID, operation string) federation.Command {
	return federation.Command{ID: core.NewID(), Incident: incident, Pool: c.Pools[0].Ref.ID, ExpectedRevision: revision, Operation: operation, Reason: "synthetic incident exercise"}
}
