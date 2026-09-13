package synthetic

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
)

// Input is an opt-in laboratory stdin channel, never an HTTP key API. Only
// counts cross the process boundary. Its caller must enforce fresh storage and
// a finite session budget. A failed store or acknowledgement terminates input;
// neither is retried, since partial provisioning may already have committed.
func Input(reader io.Reader, writer io.Writer, repo core.Repository, pair core.Association, limit int, ttl time.Duration) error {
	if limit < 1 || limit > 100000 || ttl <= 0 || ttl > time.Hour {
		return core.ErrInvalid
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 256), 256)
	total := 0
	for scanner.Scan() {
		var command struct {
			Count int `json:"count"`
		}
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&command) != nil || decoder.Decode(new(any)) != io.EOF || command.Count < 1 || command.Count > limit-total {
			return core.ErrInvalid
		}
		if err := Seed(repo, pair, command.Count, time.Now(), ttl); err != nil {
			return err
		}
		total += command.Count
		if err := json.NewEncoder(writer).Encode(map[string]any{"event": "synthetic_provisioned", "count": command.Count, "total": total}); err != nil {
			return err
		}
	}
	return scanner.Err()
}
