// Package etsi020 implements the bounded asynchronous ETSI GS QKD 020 V1.1.1 profile.
package etsi020

import (
	"encoding/base64"
	"encoding/json"
	"regexp"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
)

type Extension map[string]json.RawMessage
type Key struct {
	ID        core.KeyID `json:"key_id"`
	Value     string     `json:"value"`
	Extension Extension  `json:"extension,omitempty"`
}

func (k Key) String() string   { return "ExternalKey{material=[REDACTED]}" }
func (k Key) GoString() string { return k.String() }

type Transfer struct {
	Keys      []Key     `json:"keys"`
	Initiator string    `json:"initiator_sae_id"`
	Targets   []string  `json:"target_sae_ids"`
	Callback  string    `json:"ack_callback_url,omitempty"`
	Mandatory Extension `json:"extension_mandatory,omitempty"`
	Optional  Extension `json:"extension_optional,omitempty"`
}

func (t Transfer) String() string   { return "Transfer{material=[REDACTED]}" }
func (t Transfer) GoString() string { return t.String() }

type KeyRef struct {
	ID        core.KeyID `json:"key_id"`
	Extension Extension  `json:"extension,omitempty"`
}
type Ack struct {
	IDs       []KeyRef  `json:"key_id_container"`
	Status    string    `json:"ack_status"`
	Initiator string    `json:"initiator_sae_id"`
	Targets   []string  `json:"target_sae_ids"`
	Message   string    `json:"message,omitempty"`
	Extension Extension `json:"extension,omitempty"`
}
type Void struct {
	IDs       []core.KeyID `json:"key_ids"`
	Initiator string       `json:"initiator_sae_id"`
	Targets   []string     `json:"target_sae_ids"`
	Callback  string       `json:"ack_callback_url,omitempty"`
	All       bool         `json:"all_confirmation,omitempty"`
	Extension Extension    `json:"extension,omitempty"`
}
type VersionContainer struct {
	Versions     []string `json:"versions"`
	Capabilities []string `json:"capabilities,omitempty"`
}
type Problem struct {
	Type    string            `json:"type"`
	Status  int               `json:"status"`
	Message string            `json:"title"`
	Details map[string]string `json:"details,omitempty"`
}

type Error struct {
	Code    int
	Problem Problem
}

func (e Error) Error() string { return e.Problem.Message }
func Unsupported(detail string) error {
	return Error{503, Problem{Message: "unsupported profile option", Details: map[string]string{detail: "This option is not supported by this laboratory profile."}}}
}

var saeID = regexp.MustCompile(`^(?:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=-]|%[0-9A-Fa-f]{2}){1,64}$`)
var extensionName = regexp.MustCompile(`^E[0-9]+_.+$`)

func validExtension(e Extension) bool {
	if e == nil {
		return true
	}
	if len(e) < 1 || len(e) > 1024 {
		return false
	}
	for k := range e {
		if !extensionName.MatchString(k) {
			return false
		}
	}
	return true
}
func pair(initiator string, targets []string) error {
	if !saeID.MatchString(initiator) || len(initiator) > 64 || len(targets) == 0 {
		return core.ErrInvalid
	}
	for _, t := range targets {
		if len(t) > 64 || !saeID.MatchString(t) || t == initiator {
			return core.ErrInvalid
		}
	}
	if len(targets) != 1 {
		return Unsupported("unsupported_target_count")
	}
	return nil
}
func (t Transfer) Validate() error {
	if err := pair(t.Initiator, t.Targets); err != nil {
		return err
	}
	if len(t.Keys) < 1 || len(t.Keys) > core.MaxBatch || !validExtension(t.Mandatory) || !validExtension(t.Optional) || len(t.Callback) > 1024 {
		return core.ErrInvalid
	}
	if len(t.Mandatory) > 0 {
		return Unsupported("unsupported_mandatory_extension")
	}
	if t.Callback == "" {
		return Unsupported("synchronous_mode")
	}
	seen := map[core.KeyID]bool{}
	for _, k := range t.Keys {
		b, err := base64.StdEncoding.Strict().DecodeString(k.Value)
		valid := err == nil && len(b) == core.KeyBits/8 && base64.StdEncoding.EncodeToString(b) == k.Value
		clear(b)
		if !k.ID.Valid() || seen[k.ID] || !valid || !validExtension(k.Extension) {
			return core.ErrInvalid
		}
		seen[k.ID] = true
	}
	return nil
}
func ValidateAcks(acks []Ack) error {
	if len(acks) < 1 || len(acks) > 1024 {
		return core.ErrInvalid
	}
	seen := map[core.KeyID]bool{}
	for _, a := range acks {
		if err := pair(a.Initiator, a.Targets); err != nil {
			return err
		}
		if a.IDs == nil || len(a.IDs) > 1024 || len(a.Message) > 4096 || !validExtension(a.Extension) {
			return core.ErrInvalid
		}
		switch a.Status {
		case "relayed", "failed", "voided", "failed to void", "key not present":
		default:
			return core.ErrInvalid
		}
		for _, id := range a.IDs {
			if !id.ID.Valid() || seen[id.ID] || !validExtension(id.Extension) {
				return core.ErrInvalid
			}
			seen[id.ID] = true
		}
	}
	return nil
}
func (v Void) Validate() error {
	if err := pair(v.Initiator, v.Targets); err != nil {
		return err
	}
	if v.IDs == nil || len(v.IDs) > 1024 || len(v.Callback) > 1024 || !validExtension(v.Extension) {
		return core.ErrInvalid
	}
	if len(v.IDs) == 0 && !v.All {
		return Error{400, Problem{Message: "empty key_ids requires all_confirmation", Details: map[string]string{"no_all_confirmation": "Set all_confirmation to true to void all matching keys."}}}
	}
	if v.Callback == "" {
		return Unsupported("synchronous_mode")
	}
	seen := map[core.KeyID]bool{}
	for _, id := range v.IDs {
		if !id.Valid() || seen[id] {
			return core.ErrInvalid
		}
		seen[id] = true
	}
	return nil
}
