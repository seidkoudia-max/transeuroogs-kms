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
