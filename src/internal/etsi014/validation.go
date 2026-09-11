package etsi014

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
)

const maxBody = 64 * 1024

type requestError struct {
	status  int
	message string
}

func (e requestError) Error() string { return e.message }

func readJSON(w http.ResponseWriter, r *http.Request, dst any, allowed ...string) error {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		return requestError{415, "Content-Type must be application/json"}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			return requestError{413, "request body too large"}
		}
		return requestError{400, "invalid request body"}
	}
	if len(bytes.TrimSpace(data)) == 0 {
		data = []byte("{}")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if err := uniqueJSON(d, 0); err != nil {
		return requestError{400, "invalid or ambiguous JSON"}
	}
	if _, err := d.Token(); err != io.EOF {
		return requestError{400, "trailing JSON data"}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return requestError{400, "expected JSON object"}
	}
	for key, value := range fields {
		found := false
		for _, name := range allowed {
			if name == key {
				found = true
			}
		}
		if !found || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return requestError{400, "unknown or null request field"}
		}
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return requestError{400, "invalid request field type"}
	}
	return nil
}

// Reject duplicate members at every level before Go's JSON decoder can replace
// an earlier member. Limit nesting independently of the byte-size limit.
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting limit")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := k.(string)
			if !ok || seen[name] {
				return errors.New("duplicate JSON member")
			}
			seen[name] = true
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected delimiter")
	}
	_, err = d.Token()
	return err
}

func query(r *http.Request, allowed ...string) (url.Values, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, requestError{400, "invalid query encoding"}
	}
	for key, values := range q {
		ok := false
		for _, name := range allowed {
			if key == name {
				ok = true
			}
		}
		if !ok || len(values) != 1 || values[0] == "" {
			return nil, requestError{400, "unknown, repeated or empty query parameter"}
		}
	}
	return q, nil
}
