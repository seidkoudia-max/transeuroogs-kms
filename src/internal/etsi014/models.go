package etsi014

import "encoding/json"

type Status struct {
	SourceKMEID      string `json:"source_KME_ID"`
	TargetKMEID      string `json:"target_KME_ID"`
	MasterSAEID      string `json:"master_SAE_ID"`
	SlaveSAEID       string `json:"slave_SAE_ID"`
	KeySize          int    `json:"key_size"`
	StoredKeyCount   int    `json:"stored_key_count"`
	MaxKeyCount      int    `json:"max_key_count"`
	MaxKeyPerRequest int    `json:"max_key_per_request"`
	MaxKeySize       int    `json:"max_key_size"`
	MinKeySize       int    `json:"min_key_size"`
	MaxSAEIDCount    int    `json:"max_SAE_ID_count"`
}

type KeyRequest struct {
	Number                *int                         `json:"number"`
	Size                  *int                         `json:"size"`
	AdditionalSlaveSAEIDs []string                     `json:"additional_slave_SAE_IDs"`
	Mandatory             []map[string]json.RawMessage `json:"extension_mandatory"`
	Optional              []map[string]json.RawMessage `json:"extension_optional"`
}

type KeyID struct {
	ID        string                     `json:"key_ID"`
	Extension map[string]json.RawMessage `json:"key_ID_extension,omitempty"`
}

type KeyIDs struct {
	IDs []KeyID `json:"key_IDs"`
}

// KeyValue is the explicit delivery-only wire type. Never log it.
type KeyValue struct {
	ID  string `json:"key_ID"`
	Key string `json:"key"`
}

type KeyContainer struct {
	Keys []KeyValue `json:"keys"`
}

type Error struct {
	Message string `json:"message"`
}
