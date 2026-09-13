package eaglelab

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/synthetic"
)

// PhysicalPermit is an operator-supplied synthetic capacity budget, not provider
// evidence or a security proof. It is accepted only by the disposable emulator.
type PhysicalPermit struct {
	Schema                 string            `json:"schema"`
	LinkID                 string            `json:"link_id"`
	Synthetic              bool              `json:"synthetic"`
	InputSHA256            string            `json:"input_sha256"`
	Stations               []string          `json:"stations"`
	KeyBits                int               `json:"key_bits"`
	Count                  int               `json:"count"`
	LeftBudgetBits         int64             `json:"left_budget_bits"`
	RightBudgetBits        int64             `json:"right_budget_bits"`
	ReadyAtSimS            float64           `json:"ready_at_sim_s"`
	SecurityProofValidated bool              `json:"security_proof_validated"`
	Releases               []PhysicalRelease `json:"releases,omitempty"`
}

type PhysicalRelease struct {
	AtSimS float64 `json:"at_sim_s"`
	Count  int     `json:"count"`
}

func ReadPhysicalPermit(path string, speed float64) (PhysicalPermit, time.Duration, error) {
	var p PhysicalPermit
	f, err := os.Open(path)
	if err != nil {
		return p, 0, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(raw) > 8192 {
		return p, 0, core.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
		return p, 0, core.ErrInvalid
	}
	hash, err := hex.DecodeString(p.InputSHA256)
	expected := map[string][2]string{
		"eagle-offline-windhof-helmos": {"Windhof", "Helmos"},
		"fiber-windhof-jfk":            {"JFK", "Windhof"},
		"fiber-helmos-hellas":          {"Helmos", "HellasQCI"},
	}
	pair, known := expected[p.LinkID]
	if err != nil || len(hash) != 32 || p.InputSHA256 != hex.EncodeToString(hash) ||
		p.Schema != "transeuroogs-physical-permit-v1" || !p.Synthetic || p.SecurityProofValidated ||
		!known || len(p.Stations) != 2 || p.Stations[0] != pair[0] || p.Stations[1] != pair[1] ||
		p.KeyBits != 256 || p.Count < 0 || p.Count > 100000 ||
		p.LeftBudgetBits < int64(p.Count)*256 || p.RightBudgetBits < int64(p.Count)*256 ||
		p.LeftBudgetBits > 1e15 || p.RightBudgetBits > 1e15 ||
		math.IsNaN(p.ReadyAtSimS) || math.IsInf(p.ReadyAtSimS, 0) || p.ReadyAtSimS <= 0 || p.ReadyAtSimS > 100000 ||
		math.IsNaN(speed) || math.IsInf(speed, 0) || speed < 1 || speed > 1e6 {
		return p, 0, core.ErrInvalid
	}
	if len(p.Releases) > 1000 {
		return p, 0, core.ErrInvalid
	}
	total, previous := 0, -1.0
	for _, release := range p.Releases {
		if math.IsNaN(release.AtSimS) || math.IsInf(release.AtSimS, 0) || release.AtSimS < p.ReadyAtSimS || release.AtSimS <= previous || release.AtSimS > 100000 || release.Count < 1 || release.Count > p.Count {
			return p, 0, core.ErrInvalid
		}
		total += release.Count
		previous = release.AtSimS
	}
	if len(p.Releases) > 0 && (total != p.Count || p.Releases[0].AtSimS != p.ReadyAtSimS) {
		return p, 0, core.ErrInvalid
	}
	return p, time.Duration(p.ReadyAtSimS / speed * float64(time.Second)), nil
}

// ClaimPhysicalPermit persists an exclusive tombstone BEFORE generating keys.
// Crashes burn the permit, including crashes before readiness. A restarted
// provider fails closed; it cannot silently regenerate the same pass budget.
// The state directory must be retained by the caller for the laboratory run.
func ClaimPhysicalPermit(directory string, p PhysicalPermit) error {
	hash, hashErr := hex.DecodeString(p.InputSHA256)
	if directory == "" || hashErr != nil || len(hash) != 32 || p.InputSHA256 != hex.EncodeToString(hash) {
		return core.ErrInvalid
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	if p.LinkID != "eagle-offline-windhof-helmos" && p.LinkID != "fiber-windhof-jfk" && p.LinkID != "fiber-helmos-hellas" {
		return core.ErrInvalid
	}
	f, err := os.OpenFile(filepath.Join(directory, p.InputSHA256+"-"+p.LinkID+".claimed"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.WriteString("synthetic physical permit spent; do not replay\n"); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	d, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// SupplyPhysical fills the shared paired repository only when each modelled
// release is due. The caller must claim the permit first. The retained claim
// burns all unissued capacity if this process stops; it never resumes by reseeding.
func SupplyPhysical(ctx context.Context, repo core.Repository, pair core.Association, p PhysicalPermit, speed float64) <-chan error {
	result := make(chan error, 1)
	go func() {
		defer close(result)
		releases := p.Releases
		if len(releases) == 0 && p.Count > 0 {
			releases = []PhysicalRelease{{AtSimS: p.ReadyAtSimS, Count: p.Count}}
		}
		start := time.Now()
		for _, release := range releases {
			due := start.Add(time.Duration(release.AtSimS / speed * float64(time.Second)))
			timer := time.NewTimer(max(0, time.Until(due)))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if err := synthetic.Seed(repo, pair, release.Count, time.Now(), time.Hour); err != nil {
				result <- err
				return
			}
		}
		<-ctx.Done()
	}()
	return result
}
