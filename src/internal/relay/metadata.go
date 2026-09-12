package relay

import (
	"encoding/json"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metadata"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/peering"
)

func ProjectMetadata(c peering.Config) metadata.Projector {
	return func(raw []byte) (metadata.Projection, error) {
		var s state
		if json.Unmarshal(raw, &s) != nil || s.Keys == nil {
			return metadata.Projection{}, core.ErrInvalid
		}
		defer func() {
			for _, k := range s.Keys {
				if k != nil {
					clear(k.Material)
				}
			}
		}()
		p := metadata.Projection{Keys: map[core.KeyID]metadata.Record{}}
		for id, k := range s.Keys {
			if k == nil {
				return p, core.ErrInvalid
			}
			r := metadata.Record{Key: metadata.KeyRef{ID: id, Association: k.Pair}, SourceClass: "unknown", SourceEvidence: "unknown", CollectionIntent: k.Created, LocalExpiresAt: k.Expires, Role: k.Role, HoldingMaterial: len(k.Material) > 0, TransferIntent: k.Sent, Ready: k.Ready, Voiding: k.Voiding, Uncertain: k.Unknown}
			if peer, ok := c.Peers[k.Sender]; ok {
				r.Upstream = peer.Identity
			}
			if peer, ok := c.Peers[k.Next]; ok {
				r.NextPeer = peer.Identity
			}
			if k.Source == "synthetic-qkd" {
				r.SourceClass = "synthetic"
				r.SourceEvidence = "local_observation"
				t := k.Created
				r.GenerationTime = &t
			}
			st := core.Reserved
			if k.Ready && len(k.Material) > 0 && k.Token == "" {
				st = core.Available
			}
			if k.Voiding || k.Unknown {
				st = core.Invalid
			}
			if k.Delivered {
				st = core.Consumed
			}
			if k.Role == "source" {
				r.MasterState = st
			} else if k.Role == "target" {
				r.SlaveState = st
			}
			p.Keys[id] = r
		}
		return p, nil
	}
}
