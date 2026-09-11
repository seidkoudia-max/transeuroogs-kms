package durable

// Store commits a complete lifecycle snapshot before a repository exposes any
// side effect. Implementations must fail closed after an ambiguous write.
type Store interface {
	Save([]byte) error
	Close()
}
