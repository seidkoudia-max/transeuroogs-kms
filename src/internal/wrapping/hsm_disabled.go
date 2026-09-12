//go:build !pkcs11 || !cgo

package wrapping

// A deployment explicitly requesting HSM custody never falls back to files.
func OpenHSM(HSMConfig) (ManagedProtector, error) { return nil, ErrKey }
