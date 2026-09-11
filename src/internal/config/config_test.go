package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigurationValidation(t *testing.T) {
	valid := `{"kme_id":"LU-KMS","capacity":10,"identities":{"urn:a":"A","urn:b":"B"},"associations":[{"master":"A","slave":"B"}]}`
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"valid", valid, true},
		{"unknown field", `{"bogus":true}`, false},
		{"empty", `{}`, false},
		{"trailing data", valid + `{}`, false},
		{"ambiguous identity", `{"kme_id":"LU-KMS","capacity":10,"identities":{"urn:a":"A","urn:a2":"A"},"associations":[{"master":"A","slave":"B"}]}`, false},
		{"unknown SAE", `{"kme_id":"LU-KMS","capacity":10,"identities":{"urn:a":"A"},"associations":[{"master":"A","slave":"B"}]}`, false},
		{"duplicate association", `{"kme_id":"LU-KMS","capacity":10,"identities":{"urn:a":"A","urn:b":"B"},"associations":[{"master":"A","slave":"B"},{"master":"A","slave":"B"}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
