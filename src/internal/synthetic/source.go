// Package synthetic provisions test material; it is not a QKD device.
package synthetic

import (
	"crypto/rand"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
)

func Seed(repo core.Repository, a core.Association, count int, now time.Time, ttl time.Duration) error {
	if !a.Valid() || count < 0 || count > 100000 || ttl <= 0 {
		return core.ErrInvalid
	}
	for i := 0; i < count; i++ {
		material := make([]byte, core.KeyBits/8)
		rand.Read(material)
		err := repo.StoreKey(core.Key{ID: core.NewID(), Material: material, Association: a, Source: "synthetic-qkd", CreatedAt: now, ExpiresAt: now.Add(ttl)})
		clear(material)
		if err != nil {
			return err
		}
	}
	return nil
}
