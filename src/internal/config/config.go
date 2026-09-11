package config

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
)

type Config struct {
	KMEID        string             `json:"kme_id"`
	Capacity     int                `json:"capacity"`
	Identities   map[string]string  `json:"identities"`
	Associations []core.Association `json:"associations"`
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
	return nil
}
