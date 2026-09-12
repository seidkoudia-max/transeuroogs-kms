package metadata

import (
	"bytes"
	"encoding/json"
	"io"
)

func marshal(v any) ([]byte, error) { return json.Marshal(v) }

// Reject duplicate members, aliases, unknown members and trailing data. Signed
// payloads use this profile's exact Go JSON representation (no custom crypto).
func decode(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrEvidence
	}
	want, e := json.Marshal(out)
	var compact bytes.Buffer
	if e != nil || json.Compact(&compact, b) != nil || !bytes.Equal(want, compact.Bytes()) {
		return ErrEvidence
	}
	return nil
}

// DecodeRequest accepts ordinary JSON ordering while rejecting duplicate fields,
// unknown fields, case aliases, nulls and trailing input.
func DecodeRequest(b []byte, out any, fields ...string) error {
	d := json.NewDecoder(bytes.NewReader(b))
	if unique(d, 0) != nil {
		return ErrEvidence
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrEvidence
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(b, &object) != nil || object == nil {
		return ErrEvidence
	}
	allowed := map[string]bool{}
	for _, f := range fields {
		allowed[f] = true
	}
	for k, v := range object {
		if !allowed[k] || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return ErrEvidence
		}
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrEvidence
	}
	return nil
}

func unique(d *json.Decoder, depth int) error {
	if depth > 20 {
		return ErrEvidence
	}
	t, e := d.Token()
	if e != nil {
		return ErrEvidence
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			s, ok := k.(string)
			if e != nil || !ok || seen[s] {
				return ErrEvidence
			}
			seen[s] = true
			if unique(d, depth+1) != nil {
				return ErrEvidence
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return ErrEvidence
		}
	case json.Delim('['):
		for d.More() {
			if unique(d, depth+1) != nil {
				return ErrEvidence
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return ErrEvidence
		}
	default:
		if _, ok := t.(json.Delim); ok {
			return ErrEvidence
		}
	}
	return nil
}
