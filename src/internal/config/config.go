package config

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"slices"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metadata"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/peering"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/postgres"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/security"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/upstream"
)

type Config struct {
	KMEID        string             `json:"kme_id"`
	Capacity     int                `json:"capacity"`
	Identities   map[string]string  `json:"identities"`
	Associations []core.Association `json:"associations"`
	InterKMS     *peering.Config    `json:"inter_kms,omitempty"`
	LocalSAEs    []string           `json:"local_saes,omitempty"`
	TargetKMEs   map[string]string  `json:"target_kmes,omitempty"`
	Eagle        *upstream.Config   `json:"eagle,omitempty"`
	Operational  *Operational       `json:"operational,omitempty"`
	Metadata     *metadata.Config   `json:"metadata,omitempty"`
}

type Operational struct {
	Database         postgres.Config `json:"database"`
	CRLFiles         []string        `json:"crl_files"`
	UpstreamCRLFiles []string        `json:"upstream_crl_files,omitempty"`
	Limits           security.Limits `json:"limits"`
}

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	var c Config
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, errors.New("trailing configuration data")
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.Metadata != nil {
		if c.Metadata.Validate() != nil || (c.Operational == nil && c.Eagle == nil && c.InterKMS == nil && c.Metadata.StateDir == "") {
			return errors.New("invalid metadata configuration")
		}
		for identity, pairs := range c.Metadata.Readers {
			if _, exists := c.Identities[identity]; exists {
				return errors.New("metadata reader must have a separate identity")
			}
			for _, a := range pairs {
				if !slices.Contains(c.Associations, a) {
					return errors.New("metadata reader has unknown association")
				}
			}
		}
	}
	if c.Operational != nil {
		o := c.Operational
		if o.Database.Validate() != nil || !o.Limits.Valid() || len(o.CRLFiles) == 0 || (c.Eagle != nil && len(o.UpstreamCRLFiles) == 0) {
			return errors.New("incomplete operational configuration")
		}
	}
	if c.KMEID == "" || c.Capacity < 1 || c.Capacity > 100000 || len(c.Identities) == 0 || len(c.Associations) == 0 {
		return errors.New("incomplete KMS configuration")
	}
	saes := map[string]bool{}
	for identity, sae := range c.Identities {
		u, err := url.Parse(identity)
		if err != nil || u.Scheme != "urn" || sae == "" || saes[sae] {
			return errors.New("invalid or ambiguous SAE identity")
		}
		saes[sae] = true
	}
	seen := map[core.Association]bool{}
	for _, a := range c.Associations {
		if !a.Valid() || !saes[a.Master] || !saes[a.Slave] || seen[a] {
			return errors.New("invalid or duplicate association")
		}
		seen[a] = true
	}
	if c.InterKMS != nil {
		if c.Eagle != nil || len(c.LocalSAEs) != 0 {
			return errors.New("conflicting repository or local identity configuration")
		}
		if err := c.InterKMS.Validate(); err != nil {
			return err
		}
		for _, id := range c.InterKMS.LocalSAEs {
			if !saes[id] {
				return errors.New("unknown local SAE")
			}
		}
		for _, a := range c.Associations {
			localTarget := false
			for _, id := range c.InterKMS.LocalSAEs {
				if id == a.Slave {
					localTarget = true
				}
			}
			if !localTarget && (len(c.InterKMS.Routes[a.Slave]) == 0 || c.InterKMS.TargetKMEs[a.Slave] == "") {
				return errors.New("missing target KME or route")
			}
		}
	}
	for i, id := range c.LocalSAEs {
		if !saes[id] || slices.Contains(c.LocalSAEs[:i], id) {
			return errors.New("invalid local SAE")
		}
	}
	for sae, kme := range c.TargetKMEs {
		if !saes[sae] || kme == "" {
			return errors.New("invalid target KME identity")
		}
	}
	if c.Eagle != nil {
		if c.Eagle.Validate() != nil || len(c.Associations) != 1 || len(c.LocalSAEs) != 1 {
			return errors.New("invalid segmented service profile")
		}
		a := c.Associations[0]
		local := a.Master
		if c.Eagle.Role == "slave" {
			local = a.Slave
		}
		if c.LocalSAEs[0] != local {
			return errors.New("local SAE conflicts with association role")
		}
	}
	return nil
}
