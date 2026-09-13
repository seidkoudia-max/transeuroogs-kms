// Package testallocation supplies synthetic policy fixtures and a faultable
// snapshot store for tests. It is not used by KMS executables.
package testallocation

import (
	"bytes"
	"errors"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
)

const Actor = "urn:test:controller"

func Setup(a core.Association) *allocation.Setup {
	clock := int64(0)
	return &allocation.Setup{Issuer: "urn:test:kms", ClockUncertaintyMS: &clock, Config: allocation.Config{
		NodeID: core.NewID(), Location: "synthetic lab", MaxCommands: 100,
		Apps:       []allocation.Binding{{AppID: core.NewID(), Association: a, RemoteNodeID: core.NewID(), Rule: Rule()}},
		Principals: map[string]allocation.Principal{Actor: {Pairs: []core.Association{a}, Write: true, Routes: true}},
	}}
}
func Rule() allocation.Rule {
	return allocation.Rule{AllowedSources: []string{"synthetic", "unknown"}, AllowedIssuers: []string{}, MaxKeysPerRequest: 128}
}
func Command(a core.Association, revision uint64, rule allocation.Rule) allocation.Command {
	return allocation.Command{ID: core.NewID(), Association: a, ExpectedRevision: revision, Rule: &rule}
}

type Disk struct {
	Raw  []byte
	Fail bool
}

func (d *Disk) Save(b []byte) error {
	d.Raw = bytes.Clone(b)
	if d.Fail {
		return errors.New("ambiguous synthetic commit")
	}
	return nil
}
func (*Disk) Close() {}

const Adapter = "urn:test:adapter"

func Services(s *allocation.Setup) {
	p := s.Config.Principals[Actor]
	p.Services = true
	s.Config.Principals[Actor] = p
	a := s.Config.Apps[0]
	s.Config.Principals[Adapter] = allocation.Principal{Pairs: []core.Association{a.Association}, Telemetry: true}
	s.Config.Services = &allocation.ServiceConfig{Links: []allocation.LinkCatalog{{ID: core.NewID(), Association: a.Association, LocalInterface: 1, RemoteInterface: 2, RemoteNode: a.RemoteNodeID, Model: "synthetic test device", Technology: "DV-QKD", AdapterIdentity: Adapter, Mode: "synthetic", ObservationTTLSeconds: 60}}}
}
func Service(s *allocation.Setup, revision uint64, operation string) allocation.Command {
	ttl := uint32(3600)
	c := allocation.Command{ID: core.NewID(), ExpectedRevision: revision, Association: s.Config.Apps[0].Association, Service: &allocation.ServiceCommand{ID: s.Config.Apps[0].AppID, Operation: operation}}
	if operation == "application_create" || operation == "application_update" {
		c.Service.TTL = &ttl
	}
	return c
}
