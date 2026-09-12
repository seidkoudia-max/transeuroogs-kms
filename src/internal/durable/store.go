package durable

import "encoding/json"

// PlainSnapshot prevents silently discarding managed metadata on restart.
func PlainSnapshot(raw []byte) bool {
	if raw == nil {
		return true
	}
	var fields map[string]json.RawMessage
	defer func() {
		for _, value := range fields {
			clear(value)
		}
	}()
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	_, managed := fields["Provenance"]
	return !managed
}

// Store commits a complete lifecycle snapshot before a repository exposes any
// side effect. Implementations must fail closed after an ambiguous write.
type Store interface {
	Save([]byte) error
	Close()
}
