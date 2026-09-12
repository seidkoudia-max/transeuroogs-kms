package ingest

import (
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/wrapping"
	"os"
	"path/filepath"
	"strings"
)

// EvidenceFiles connects a reviewed local provider adapter to the KMS without
// inventing an SES HTTP endpoint. The adapter writes signed normalized evidence
// as <unchanged UUIDv4>.jws (0600) in this private directory (0700). The KMS still
// verifies signature, issuer, service, epoch, pairing, readiness and validity.
// No consuming requests are sent while looking up evidence or recovery status.
type EvidenceFiles struct {
	Provider
	Directory string
}

func (p *EvidenceFiles) Evidence(ids []core.KeyID) (map[core.KeyID]string, error) {
	info, e := os.Lstat(p.Directory)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, core.ErrUnavailable
	}
	out := map[core.KeyID]string{}
	for _, id := range ids {
		if !id.Valid() {
			return nil, core.ErrInvalid
		}
		b, e := wrapping.PrivateRead(filepath.Join(p.Directory, string(id)+".jws"), 16384)
		if e != nil {
			return nil, core.ErrUnavailable
		}
		out[id] = strings.TrimSpace(string(b))
	}
	return out, nil
}
