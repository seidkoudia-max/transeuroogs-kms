//go:build pkcs11 && cgo

package wrapping

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"github.com/miekg/pkcs11"
	"strings"
	"sync"
)

type hsm struct {
	initialized bool
	mu          sync.Mutex
	c           HSMConfig
	p           *pkcs11.Ctx
	session     pkcs11.SessionHandle
	keys        map[string]pkcs11.ObjectHandle
	broken      bool
}
type hsmEnvelope struct {
	Version    int    `json:"version"`
	KeyID      string `json:"key_id"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func OpenHSM(c HSMConfig) (ManagedProtector, error) {
	if c.Validate() != nil {
		return nil, ErrKey
	}
	pin, e := PrivateRead(c.PINFile, 1024)
	defer clear(pin)
	if e != nil || len(pin) == 0 {
		return nil, ErrKey
	}
	h := &hsm{c: c, keys: map[string]pkcs11.ObjectHandle{}, p: pkcs11.New(c.Module)}
	if h.p == nil {
		return nil, ErrKey
	}
	ok := false
	defer func() {
		if !ok {
			h.Close()
		}
	}()
	if h.p.Initialize() != nil {
		return nil, ErrKey
	}
	h.initialized = true
	slots, e := h.p.GetSlotList(true)
	if e != nil {
		return nil, ErrKey
	}
	found := false
	var slot uint
	for _, s := range slots {
		info, e := h.p.GetTokenInfo(s)
		if e == nil && strings.TrimSpace(info.Label) == c.TokenLabel {
			if found {
				return nil, ErrKey
			}
			slot = s
			found = true
		}
	}
	if !found {
		return nil, ErrKey
	}
	h.session, e = h.p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if e != nil {
		return nil, ErrKey
	}
	if h.p.Login(h.session, pkcs11.CKU_USER, strings.TrimSpace(string(pin))) != nil {
		return nil, ErrKey
	}
	for id, label := range c.Keys {
		template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY), pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES), pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)}
		if h.p.FindObjectsInit(h.session, template) != nil {
			return nil, ErrKey
		}
		objects, _, e := h.p.FindObjects(h.session, 2)
		finish := h.p.FindObjectsFinal(h.session)
		if e != nil || finish != nil || len(objects) != 1 {
			return nil, ErrKey
		}
		want := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true), pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false), pkcs11.NewAttribute(pkcs11.CKA_LOCAL, true), pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32), pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true), pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true)}
		query := make([]*pkcs11.Attribute, len(want))
		for i, a := range want {
			query[i] = pkcs11.NewAttribute(a.Type, nil)
		}
		got, e := h.p.GetAttributeValue(h.session, objects[0], query)
		if e != nil || len(got) != len(want) {
			return nil, ErrKey
		}
		for i, a := range got {
			if a.Type != want[i].Type || !bytes.Equal(a.Value, want[i].Value) {
				return nil, ErrKey
			}
		}
		h.keys[id] = objects[0]
	}
	ok = true
	return h, nil
}
func (h *hsm) aad(id string, aad []byte) []byte {
	return append([]byte("transeuroogs-pkcs11-v1:"+id+":"), aad...)
}
func (h *hsm) Seal(raw, aad []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.broken || h.p == nil {
		return nil, ErrKey
	}
	nonce := make([]byte, 12)
	rand.Read(nonce)
	params := pkcs11.NewGCMParams(nonce, h.aad(h.c.Active, aad), 128)
	defer params.Free()
	if h.p.EncryptInit(h.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, h.keys[h.c.Active]) != nil {
		h.broken = true
		return nil, ErrKey
	}
	blob, e := h.p.Encrypt(h.session, raw)
	if e != nil || len(blob) != len(raw)+16 {
		h.broken = true
		return nil, ErrKey
	}
	iv := params.IV()
	if len(iv) != 12 {
		h.broken = true
		return nil, ErrKey
	}
	return json.Marshal(hsmEnvelope{2, h.c.Active, iv, blob})
}
func (h *hsm) Open(blob, aad []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.broken || h.p == nil {
		return nil, ErrKey
	}
	var env hsmEnvelope
	if json.Unmarshal(blob, &env) != nil || env.Version != 2 || len(env.Nonce) != 12 || len(env.Ciphertext) < 16 {
		return nil, ErrKey
	}
	key, ok := h.keys[env.KeyID]
	if !ok {
		return nil, ErrKey
	}
	params := pkcs11.NewGCMParams(env.Nonce, h.aad(env.KeyID, aad), 128)
	defer params.Free()
	if h.p.DecryptInit(h.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, key) != nil {
		h.broken = true
		return nil, ErrKey
	}
	raw, e := h.p.Decrypt(h.session, env.Ciphertext)
	if e != nil {
		clear(raw)
		h.broken = true
		return nil, ErrKey
	}
	return raw, nil
}
func (h *hsm) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.broken = true
	if h.p != nil {
		if h.session != 0 {
			_ = h.p.Logout(h.session)
			_ = h.p.CloseSession(h.session)
		}
		if h.initialized {
			_ = h.p.Finalize()
		}
		h.p.Destroy()
		h.p = nil
	}
}
