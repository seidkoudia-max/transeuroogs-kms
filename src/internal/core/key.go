// Package core defines the KMS domain without transport or storage dependencies.
package core

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const KeyBits = 256
const MaxBatch = 128

var (
	ErrInvalid      = errors.New("invalid key request")
	ErrDuplicate    = errors.New("duplicate key ID")
	ErrUnavailable  = errors.New("key material unavailable")
	ErrUnauthorized = errors.New("unauthorized association")
	ErrCapacity     = errors.New("repository lifetime capacity reached")
)

type KeyID string

// NewID uses the standard-library CSPRNG and the UUIDv4 data format.
func NewID() KeyID {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return KeyID(fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]))
}

func (id KeyID) Valid() bool {
	s := string(id)
	if len(s) != 36 || s != strings.ToLower(s) || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return err == nil && len(b) == 16 && b[6]>>4 == 4 && b[8]>>6 == 2
}

type State string

const (
	Available State = "AVAILABLE"
	Reserved  State = "RESERVED"
	Consumed  State = "CONSUMED"
	Invalid   State = "INVALID"
	Expired   State = "EXPIRED"
)

func (s State) Terminal() bool { return s == Consumed || s == Invalid || s == Expired }

type Association struct {
	Master string `json:"master"`
	Slave  string `json:"slave"`
}

func (a Association) Valid() bool {
	return validName(a.Master) && validName(a.Slave) && a.Master != a.Slave
}

func validName(s string) bool {
	return len(s) > 0 && len(s) <= 128 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\r\n\x00")
}

type Key struct {
	ID          KeyID
	Material    []byte `json:"-"`
	Association Association
	Source      string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

func (k Key) String() string   { return fmt.Sprintf("Key{id=%s material=[REDACTED]}", k.ID) }
func (k Key) GoString() string { return k.String() }

func (k Key) Validate(now time.Time) error {
	if !k.ID.Valid() || len(k.Material)*8 != KeyBits || !k.Association.Valid() || !validName(k.Source) || k.CreatedAt.IsZero() || k.CreatedAt.After(now) || !k.ExpiresAt.After(now) || !k.ExpiresAt.After(k.CreatedAt) {
		return ErrInvalid
	}
	return nil
}

type Delivery struct {
	ID       KeyID
	Material []byte `json:"-"`
}

func (d Delivery) String() string   { return fmt.Sprintf("Delivery{id=%s material=[REDACTED]}", d.ID) }
func (d Delivery) GoString() string { return d.String() }

type Metadata struct {
	ID          KeyID
	Association Association
	Source      string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	MasterState State
	SlaveState  State
}

type Reservation struct {
	Token KeyID
	IDs   []KeyID
}

type Inventory struct {
	Available int
	Capacity  int
}

// Repository operations are atomic across each entire batch. Implementations
// retain terminal ID tombstones and return owned copies of delivery material.
type Repository interface {
	StoreKey(Key) error
	ReserveKeys(Association, int) (Reservation, error)
	ConsumeReservation(Association, KeyID) ([]Delivery, error)
	ConsumePeerKeys(Association, []KeyID) ([]Delivery, error)
	InvalidateKey(KeyID) error
	Metadata(KeyID) (Metadata, error)
	Inventory(Association) Inventory
}
