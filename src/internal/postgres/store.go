// Package postgres persists lifecycle snapshots transactionally. A session lock
// fences a second writer; loss of the connection permanently poisons the store.
package postgres

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/wrapping"
)

//go:embed schema.sql
var schema embed.FS

type Config struct {
	DSNFile          string `json:"dsn_file"`
	Namespace        string `json:"namespace"`
	CheckpointDir    string `json:"checkpoint_dir"`
	WrappingKeyDir   string `json:"wrapping_key_dir"`
	AllowLocalSocket bool   `json:"allow_local_socket,omitempty"`
}

func (c Config) Validate() error {
	if c.DSNFile == "" || c.CheckpointDir == "" || c.WrappingKeyDir == "" || len(c.Namespace) < 1 || len(c.Namespace) > 128 || strings.ContainsAny(c.Namespace, "\x00\r\n") {
		return core.ErrInvalid
	}
	return nil
}

type checkpoint struct {
	Namespace  string
	Generation string
	Version    int64
	Digest     string
}
type Store struct {
	mu        sync.Mutex
	conn      *pgx.Conn
	anchor    *durable.Journal
	protector wrapping.Protector
	c         checkpoint
	broken    bool
}

func connection(c Config) (*pgx.Conn, error) {
	b, err := wrapping.PrivateRead(c.DSNFile, 16384)
	defer clear(b)
	if err != nil {
		return nil, durable.ErrState
	}
	config, err := pgx.ParseConfig(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, durable.ErrState
	}
	// No TCP plaintext, sslmode=prefer/require, TLS fallback or custom verifier.
	local := c.AllowLocalSocket && strings.HasPrefix(config.Host, "/")
	if !local && (config.TLSConfig == nil || config.TLSConfig.InsecureSkipVerify || len(config.Fallbacks) > 0) {
		return nil, durable.ErrState
	}
	config.ConnectTimeout = 5 * time.Second
	config.RuntimeParams["statement_timeout"] = "5000"
	config.RuntimeParams["lock_timeout"] = "2000"
	config.RuntimeParams["synchronous_commit"] = "on"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, durable.ErrState
	}
	return conn, nil
}

// Migrate is a separate operator action; the serving process never runs DDL.
func Migrate(c Config) error {
	conn, err := connection(c)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	sql, _ := schema.ReadFile("schema.sql")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = conn.Exec(ctx, string(sql))
	if err != nil {
		return durable.ErrState
	}
	return nil
}

func Open(c Config, initialize bool) (*Store, []byte, error) {
	return OpenProtected(c, initialize, wrapping.FileRing{Dir: c.WrappingKeyDir})
}
func OpenProtected(c Config, initialize bool, protector wrapping.Protector) (s *Store, raw []byte, err error) {
	if c.Validate() != nil || protector == nil {
		return nil, nil, core.ErrInvalid
	}
	s = &Store{protector: protector}
	ok := false
	owned := s
	defer func() {
		if !ok {
			owned.Close()
		}
	}()
	conn, e := connection(c)
	if e != nil {
		return nil, nil, e
	}
	s.conn = conn
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var locked bool
	if conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1, 0))", c.Namespace).Scan(&locked) != nil || !locked {
		return nil, nil, durable.ErrState
	}
	var meta, blob []byte
	s.c.Namespace = c.Namespace
	e = conn.QueryRow(ctx, `SELECT m.generation,m.version,m.metadata,s.ciphertext FROM kms_meta.state m JOIN kms_secret.state s USING(namespace) WHERE namespace=$1`, c.Namespace).Scan(&s.c.Generation, &s.c.Version, &meta, &blob)
	fresh := errors.Is(e, pgx.ErrNoRows)
	if (fresh && !initialize) || (e != nil && !fresh) {
		return nil, nil, durable.ErrState
	}
	if !fresh {
		info, statErr := os.Lstat(filepath.Join(c.CheckpointDir, "state.enc"))
		if statErr != nil || !info.Mode().IsRegular() {
			return nil, nil, durable.ErrState
		}
	}
	j, anchor, openErr := durable.Open(c.CheckpointDir, "transeuroogs-postgres-checkpoint-v1")
	if openErr != nil {
		return nil, nil, openErr
	}
	s.anchor = j
	defer clear(anchor)
	if errors.Is(e, pgx.ErrNoRows) {
		if !initialize || anchor != nil {
			return nil, nil, durable.ErrState
		}
		s.c.Generation = string(core.NewID())
		s.c.Version = 0
		// Provisioning commits an empty snapshot and checkpoint. After a crash,
		// missing or mismatched components require recovery, never reseeding.
		if e = s.saveLocked(nil, true); e != nil {
			return nil, nil, e
		}
		ok = true
		return s, nil, nil
	}
	if e != nil || anchor == nil {
		return nil, nil, durable.ErrState
	}
	var normalized any
	if json.Unmarshal(meta, &normalized) != nil {
		return nil, nil, durable.ErrState
	}
	meta, _ = json.Marshal(normalized)
	var a checkpoint
	if json.Unmarshal(anchor, &a) != nil || a.Namespace != s.c.Namespace || a.Generation != s.c.Generation || a.Version != s.c.Version || a.Digest != digest(blob) {
		return nil, nil, durable.ErrState
	}
	s.c = a
	raw, e = protector.Open(blob, s.aad(meta))
	if e != nil {
		return nil, nil, durable.ErrState
	}
	if len(raw) == 0 {
		raw = nil
	}
	ok = true
	return s, raw, nil
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func (s *Store) aad(meta []byte) []byte {
	return []byte(s.c.Namespace + ":" + s.c.Generation + ":" + strconv.FormatInt(s.c.Version, 10) + ":" + digest(meta))
}

// publicMetadata is an allowlist, not a blacklist. Protocol extensions, key
// bytes, fingerprints and reservation tokens never enter the metadata schema.
func publicMetadata(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return []byte(`{"keys":{}}`), nil
	}
	var snapshot map[string]json.RawMessage
	if json.Unmarshal(raw, &snapshot) != nil {
		return nil, core.ErrInvalid
	}
	var keys map[string]map[string]json.RawMessage
	if json.Unmarshal(snapshot["Keys"], &keys) != nil {
		return nil, core.ErrInvalid
	}
	public := map[string]map[string]json.RawMessage{}
	for id, k := range keys {
		if !core.KeyID(id).Valid() {
			return nil, core.ErrInvalid
		}
		if m := k["Meta"]; m != nil {
			if json.Unmarshal(m, &k) != nil {
				return nil, core.ErrInvalid
			}
		}
		v := map[string]json.RawMessage{}
		for _, name := range []string{"Association", "Pair", "Role", "State", "MasterState", "SlaveState", "Created", "Expires", "CreatedAt", "ExpiresAt", "Delivered", "Ready", "Voiding", "Unknown"} {
			if b := k[name]; b != nil {
				v[name] = b
			}
		}
		public[id] = v
	}
	return json.Marshal(map[string]any{"keys": public})
}
func (s *Store) saveLocked(raw []byte, initial bool) error {
	if s.broken || s.conn == nil || s.conn.IsClosed() {
		return durable.ErrState
	}
	meta, err := publicMetadata(raw)
	if err != nil {
		return err
	}
	previous := s.c.Version
	if !initial {
		s.c.Version++
	}
	blob, err := s.protector.Seal(raw, s.aad(meta))
	if err != nil {
		s.broken = true
		return durable.ErrState
	}
	s.c.Digest = digest(blob)
	anchor, _ := json.Marshal(s.c)
	// Write-ahead checkpoint: even an uncertain COMMIT cannot permit an old
	// database backup to revive consumed keys. A mismatch fails startup closed.
	if err = s.anchor.Save(anchor); err != nil {
		s.broken = true
		return durable.ErrState
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.conn.Begin(ctx)
	if err != nil {
		s.broken = true
		return durable.ErrState
	}
	defer tx.Rollback(context.Background())
	if initial {
		_, err = tx.Exec(ctx, `INSERT INTO kms_meta.state VALUES($1,$2,$3,$4)`, s.c.Namespace, s.c.Generation, s.c.Version, meta)
		if err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO kms_secret.state VALUES($1,$2)`, s.c.Namespace, blob)
		}
	} else {
		var n int64
		tag, e := tx.Exec(ctx, `UPDATE kms_meta.state SET version=$1,metadata=$2 WHERE namespace=$3 AND generation=$4 AND version=$5`, s.c.Version, meta, s.c.Namespace, s.c.Generation, previous)
		err = e
		n = tag.RowsAffected()
		if err == nil && n != 1 {
			err = durable.ErrState
		}
		if err == nil {
			tag, err = tx.Exec(ctx, `UPDATE kms_secret.state SET ciphertext=$1 WHERE namespace=$2`, blob, s.c.Namespace)
			if err == nil && tag.RowsAffected() != 1 {
				err = durable.ErrState
			}
		}
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO kms_audit.events(namespace,request_id,actor,operation,phase,status,version) VALUES($1,'','repository','snapshot','commit',0,$2)`, s.c.Namespace, s.c.Version)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		s.broken = true
		return durable.ErrState
	}
	return nil
}
func (s *Store) Save(raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(raw, false)
}
func (s *Store) Record(requestID, actor, operation, phase string, status int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken || s.conn == nil || len(actor) > 256 || len(operation) > 64 || len(phase) > 32 || !core.KeyID(requestID).Valid() {
		return durable.ErrState
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.conn.Exec(ctx, `INSERT INTO kms_audit.events(namespace,request_id,actor,operation,phase,status,version) VALUES($1,$2,$3,$4,$5,$6,$7)`, s.c.Namespace, requestID, actor, operation, phase, status, s.c.Version)
	if err != nil {
		s.broken = true
		return durable.ErrState
	}
	return nil
}
func (s *Store) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.broken = true
	if s.conn != nil {
		s.conn.Close(context.Background())
		s.conn = nil
	}
	if s.anchor != nil {
		s.anchor.Close()
		s.anchor = nil
	}
}
