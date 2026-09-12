//go:build pkcs11 && cgo

package wrapping

import (
	"bytes"
	"github.com/miekg/pkcs11"
	"os"
	"path/filepath"
	"testing"
)

func TestSoftHSMNonExportableAESAndRotation(t *testing.T) {
	module := os.Getenv("KMS_TEST_PKCS11_MODULE")
	if module == "" {
		t.Skip("KMS_TEST_PKCS11_MODULE required")
	}
	dir := t.TempDir()
	tokens := filepath.Join(dir, "tokens")
	if e := os.Mkdir(tokens, 0700); e != nil {
		t.Fatal(e)
	}
	conf := filepath.Join(dir, "softhsm.conf")
	if e := os.WriteFile(conf, []byte("directories.tokendir = "+tokens+"\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n"), 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("SOFTHSM2_CONF", conf)
	// Test-only PINs and token objects are generated in a disposable directory.
	p := pkcs11.New(module)
	if p == nil {
		t.Fatal("module unavailable")
	}
	if e := p.Initialize(); e != nil {
		t.Fatal("module initialization failed")
	}
	slots, e := p.GetSlotList(true)
	if e != nil || len(slots) == 0 {
		t.Fatal("no test token slot")
	}
	if p.InitToken(slots[0], "synthetic-so-pin", "transeuroogs-test") != nil {
		t.Fatal("test token initialization")
	}
	slots, _ = p.GetSlotList(true)
	session, e := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if e != nil {
		t.Fatal("session")
	}
	if p.Login(session, pkcs11.CKU_SO, "synthetic-so-pin") != nil || p.InitPIN(session, "synthetic-user-pin") != nil {
		t.Fatal("test PIN initialization")
	}
	_ = p.Logout(session)
	if p.Login(session, pkcs11.CKU_USER, "synthetic-user-pin") != nil {
		t.Fatal("test login")
	}
	for _, label := range []string{"test-v1", "test-v2"} {
		attrs := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label), pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true), pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false), pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32), pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true), pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true)}
		if _, e = p.GenerateKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, attrs); e != nil {
			t.Fatal("synthetic token key generation")
		}
	}
	_ = p.Logout(session)
	_ = p.CloseSession(session)
	_ = p.Finalize()
	p.Destroy()
	pin := filepath.Join(dir, "pin")
	_ = os.WriteFile(pin, []byte("synthetic-user-pin"), 0600)
	c := HSMConfig{Module: module, TokenLabel: "transeuroogs-test", PINFile: pin, Active: "v1", Keys: map[string]string{"v1": "test-v1", "v2": "test-v2"}}
	h, e := OpenHSM(c)
	if e != nil {
		t.Fatal("HSM open", e)
	}
	plain := bytes.Repeat([]byte{7}, 128)
	sealed, e := h.Seal(plain, []byte("namespace:1"))
	if e != nil {
		t.Fatal("seal", e)
	}
	h.Close()
	c.Active = "v2"
	h, e = OpenHSM(c)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	raw, e := h.Open(sealed, []byte("namespace:1"))
	if e != nil || !bytes.Equal(raw, plain) {
		t.Fatal("retired wrapping generation unavailable", e)
	}
	clear(raw)
	newBlob, e := h.Seal(plain, []byte("namespace:2"))
	if e != nil || bytes.Equal(newBlob, sealed) {
		t.Fatal("rotation", e)
	}
	if raw, e = h.Open(sealed, []byte("wrong namespace")); e == nil || len(raw) > 0 {
		t.Fatal("AAD mismatch accepted")
	}
	if _, e = h.Seal(plain, nil); e == nil {
		t.Fatal("failed HSM stayed usable")
	}
}
