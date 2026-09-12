package storage

import (
	"encoding/json"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metadata"
)

func ProjectMetadata(raw []byte) (metadata.Projection, error) {
	var s memoryState
	if json.Unmarshal(raw, &s) != nil || s.Keys == nil {
		return metadata.Projection{}, core.ErrInvalid
	}
	defer func() {
		for _, k := range s.Keys {
			clear(k.MasterMaterial)
			clear(k.SlaveMaterial)
		}
	}()
	p := metadata.Projection{Keys: map[core.KeyID]metadata.Record{}}
	if s.Allocation != nil {
		p.Controls = s.Allocation.Commits
	}
	for id, k := range s.Keys {
		m := k.Meta
		r := metadata.Record{Key: metadata.KeyRef{Pool: m.Pool, ID: id, Association: m.Association}, SourceClass: "unknown", SourceEvidence: "unknown", CollectionIntent: m.CreatedAt, LocalExpiresAt: m.ExpiresAt, Role: "local", MasterState: m.MasterState, SlaveState: m.SlaveState, HoldingMaterial: len(k.MasterMaterial) > 0 || len(k.SlaveMaterial) > 0}
		if m.Source == "synthetic-qkd" {
			r.SourceClass = "synthetic"
			r.SourceEvidence = "local_observation"
			t := m.CreatedAt
			r.GenerationTime = &t
		}
		p.Keys[id] = r
	}
	metadata.ProjectProtection(&p, s.Protection)
	return p, nil
}
