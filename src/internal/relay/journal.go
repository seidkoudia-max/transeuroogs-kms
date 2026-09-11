package relay

import "github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"

type journal struct{ *durable.Journal }

var errJournal = durable.ErrState

func openJournal(dir string) (*journal, []byte, error) {
	j, raw, err := durable.Open(dir, "transeuroogs-relay-state-v1")
	if err != nil {
		return nil, nil, err
	}
	return &journal{j}, raw, nil
}
func (j *journal) save(raw []byte) error { return j.Save(raw) }
func (j *journal) close() {
	if j != nil {
		j.Close()
	}
}
