package ingest

import (
	"encoding/json"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metadata"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/upstream"
)

func ProjectMetadata(c upstream.Config, a core.Association) metadata.Projector {
	return func(raw []byte) (metadata.Projection, error) {
		var s state
		if json.Unmarshal(raw, &s) != nil || s.Keys == nil || s.Requests == nil {
			return metadata.Projection{}, core.ErrInvalid
		}
		defer func() {
			for _, k := range s.Keys {
				if k != nil {
					clear(k.Material)
				}
			}
		}()
		p := metadata.Projection{Keys: map[core.KeyID]metadata.Record{}, Attempts: map[string]metadata.Attempt{}}
		uncertain := map[core.KeyID]bool{}
		for token, q := range s.Requests {
			if q == nil {
				return p, core.ErrInvalid
			}
			p.Attempts[string(token)] = metadata.Attempt{ID: string(token), Association: a, IDs: q.IDs, Count: q.Count, Status: q.Status, Started: q.Started}
			if q.Status == "pending" || q.Status == "uncertain" {
				for _, id := range q.IDs {
					uncertain[id] = true
				}
			}
		}
		for id, k := range s.Keys {
			if k == nil {
				return p, core.ErrInvalid
			}
			r := metadata.Record{Key: metadata.KeyRef{ID: id, Association: a}, SourceClass: "synthetic", SourceEvidence: "unverified_claim", CollectionIntent: k.Created, LocalExpiresAt: k.Expires, Role: "ingest_" + c.Role, HoldingMaterial: len(k.Material) > 0, Upstream: c.ServerIdentity, Uncertain: uncertain[id]}
			if c.Role == "master" {
				r.MasterState = k.State
			} else {
				r.SlaveState = k.State
			}
			p.Keys[id] = r
		}
		return p, nil
	}
}
