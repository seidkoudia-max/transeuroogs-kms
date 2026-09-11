// Package eaglelab simulates the observable service outcome of offline satellite
// relay. It does not implement SES authentication, cryptography or satellite links.
package eaglelab

import (
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"time"
)

// Delayed hides paired synthetic inventory until the modelled service is ready.
type Delayed struct {
	core.Repository
	ReadyAt time.Time
	Now     func() time.Time
}

func (d *Delayed) ready() bool {
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	return !now().Before(d.ReadyAt)
}
func (d *Delayed) ReserveKeys(a core.Association, n int) (core.Reservation, error) {
	if !d.ready() {
		return core.Reservation{}, core.ErrUnavailable
	}
	return d.Repository.ReserveKeys(a, n)
}
func (d *Delayed) ConsumeReservation(a core.Association, t core.KeyID) ([]core.Delivery, error) {
	if !d.ready() {
		return nil, core.ErrUnavailable
	}
	return d.Repository.ConsumeReservation(a, t)
}
func (d *Delayed) ConsumePeerKeys(a core.Association, ids []core.KeyID) ([]core.Delivery, error) {
	if !d.ready() {
		return nil, core.ErrUnavailable
	}
	return d.Repository.ConsumePeerKeys(a, ids)
}
func (d *Delayed) Inventory(a core.Association) core.Inventory {
	i := d.Repository.Inventory(a)
	if !d.ready() {
		i.Available = 0
	}
	return i
}
