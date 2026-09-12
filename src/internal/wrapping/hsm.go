package wrapping

import "path/filepath"

// HSMConfig contains module/credential references, never the PIN or key bytes.
// Keys are pre-provisioned AES-256 token objects. The KMS never generates,
// imports, exports or deletes production HSM keys.
type HSMConfig struct {
	Module     string            `json:"module"`
	TokenLabel string            `json:"token_label"`
	PINFile    string            `json:"pin_file"`
	Active     string            `json:"active_key_id"`
	Keys       map[string]string `json:"key_labels"`
}

func (c HSMConfig) Validate() error {
	if !filepath.IsAbs(c.Module) || c.TokenLabel == "" || len(c.TokenLabel) > 32 || c.PINFile == "" || !name.MatchString(c.Active) || c.Keys[c.Active] == "" || len(c.Keys) > 32 {
		return ErrKey
	}
	seen := map[string]bool{}
	for id, label := range c.Keys {
		if !name.MatchString(id) || label == "" || len(label) > 128 || seen[label] {
			return ErrKey
		}
		seen[label] = true
	}
	return nil
}

type ManagedProtector interface {
	Protector
	Close()
}
