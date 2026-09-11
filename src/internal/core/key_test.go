package core

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestKeyValidationAndRedaction(t *testing.T) {
	now := time.Now()
	k := Key{ID: NewID(), Material: []byte(strings.Repeat("x", 32)), Association: Association{"A", "B"}, Source: "synthetic", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := k.Validate(now); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{fmt.Sprint(k), fmt.Sprintf("%+v", k), fmt.Sprintf("%#v", k)} {
		if !strings.Contains(s, "REDACTED") || strings.Contains(s, string(k.Material)) {
			t.Fatal("material formatting leak")
		}
	}
	for _, v := range []any{k, Delivery{ID: k.ID, Material: k.Material}} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "Material") || strings.Contains(string(b), "eHh4") {
			t.Fatal("material JSON leak")
		}
	}
	for name, change := range map[string]func(*Key){
		"bad id":          func(k *Key) { k.ID = "invalid" },
		"bad size":        func(k *Key) { k.Material = []byte{0} },
		"same sae":        func(k *Key) { k.Association.Slave = k.Association.Master },
		"future creation": func(k *Key) { k.CreatedAt = now.Add(time.Second) },
		"expired":         func(k *Key) { k.ExpiresAt = now },
		"no source":       func(k *Key) { k.Source = "" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := k
			change(&copy)
			if copy.Validate(now) == nil {
				t.Fatal("invalid key accepted")
			}
		})
	}
}

func TestUUIDs(t *testing.T) {
	seen := map[KeyID]bool{}
	for range 1000 {
		id := NewID()
		if !id.Valid() || seen[id] {
			t.Fatal("invalid or duplicate UUID")
		}
		seen[id] = true
	}
	for _, id := range []KeyID{"", "550e8400-e29b-41d4-a716-44665544000z", "550E8400-e29b-41d4-a716-446655440000", "550e8400-e29b-11d4-a716-446655440000"} {
		if id.Valid() {
			t.Fatal("invalid UUID accepted")
		}
	}
}
