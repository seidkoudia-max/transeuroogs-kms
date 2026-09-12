package witness

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testallocation"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCASConcurrentWriterRestartRollbackAndFailedCommit(t *testing.T) {
	d := &testallocation.Disk{}
	a, e := Open(d, nil)
	if e != nil {
		t.Fatal(e)
	}
	f := Fence{Namespace: "LU", Generation: string(core.NewID()), Version: 0, Digest: strings.Repeat("1", 64), Witnessed: true}
	if e = a.Advance(Fence{}, f); e != nil {
		t.Fatal(e)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for n := range 12 {
		wg.Go(func() {
			next := f
			next.Version++
			next.Digest = strings.Repeat(string("23456789abcd"[n]), 64)
			if a.Advance(f, next) == nil {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("multiple writers advanced same fence")
	}
	newest, e := a.Current("LU")
	if e != nil {
		t.Fatal(e)
	}
	a.Close()
	a, e = Open(d, bytes.Clone(d.Raw))
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	if e = a.Advance(newest, f); e == nil {
		t.Fatal("rollback accepted")
	}
	if e = a.Advance(Fence{}, f); e == nil {
		t.Fatal("old generation reinitialized")
	}
	if e = a.Advance(f, newest); e != nil {
		t.Fatal("exact CAS replay lost", e)
	}
	d.Fail = true
	next := newest
	next.Version++
	if e = a.Advance(newest, next); e == nil {
		t.Fatal("uncertain witness commit acknowledged")
	}
	if _, e = a.Current("LU"); e == nil {
		t.Fatal("poisoned authority remained readable")
	}
}

func TestWitnessHTTPNamespaceScopeAndPrecondition(t *testing.T) {
	a, _ := Open(&testallocation.Disk{}, nil)
	defer a.Close()
	h := Handler(a, map[string][]string{"urn:test:writer": {"LU"}})
	f := Fence{Namespace: "LU", Generation: string(core.NewID()), Digest: strings.Repeat("1", 64), Witnessed: true}
	b, _ := json.Marshal(f)
	request := func(actor, method, path, condition, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("If-Match", condition)
		if actor != "" {
			u, _ := url.Parse(actor)
			r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u}}}}}
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("", "PUT", "/checkpoints/LU", tag(Fence{}), string(b)); w.Code != 401 {
		t.Fatal("missing mTLS accepted")
	}
	if w := request("urn:test:writer", "GET", "/checkpoints/GR", "", ""); w.Code != 403 {
		t.Fatal("cross-domain read")
	}
	if w := request("urn:test:writer", "PUT", "/checkpoints/LU", "", string(b)); w.Code != 412 {
		t.Fatal("missing CAS precondition")
	}
	if w := request("urn:test:writer", "PUT", "/checkpoints/LU", tag(Fence{}), string(b)); w.Code != 200 {
		t.Fatal("CAS failed", w.Code)
	}
	old := f
	f.Version++
	b, _ = json.Marshal(f)
	if w := request("urn:test:writer", "PUT", "/checkpoints/LU", tag(Fence{}), string(b)); w.Code != 412 {
		t.Fatal("stale writer accepted")
	}
	if w := request("urn:test:writer", "PUT", "/checkpoints/LU", tag(old), string(b)); w.Code != 200 {
		t.Fatal("advance", w.Code)
	}
}
