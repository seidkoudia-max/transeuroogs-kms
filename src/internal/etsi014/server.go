// Package etsi014 translates the initial application-facing profile to core operations.
package etsi014

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/config"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/security"
)

type Server struct {
	repo       core.Repository
	kme        string
	identities map[string]string
	allowed    map[core.Association]bool
}

func New(repo core.Repository, c config.Config) (http.Handler, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if repo == nil {
		return nil, core.ErrInvalid
	}
	s := &Server{repo: repo, kme: c.KMEID, identities: map[string]string{}, allowed: map[core.Association]bool{}}
	for uri, id := range c.Identities {
		s.identities[uri] = id
	}
	for _, a := range c.Associations {
		s.allowed[a] = true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/keys/{sae}/status", s.status)
	for _, method := range []string{"GET", "POST"} {
		mux.HandleFunc(method+" /api/v1/keys/{sae}/enc_keys", s.enc)
		mux.HandleFunc(method+" /api/v1/keys/{sae}/dec_keys", s.dec)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Go's GET patterns also match HEAD; key retrieval must never run on HEAD.
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			write(w, 405, Error{Message: "method not allowed"})
			return
		}
		if _, ok := security.SAEIdentity(r, s.identities); !ok {
			write(w, 401, Error{Message: "unauthorized"})
			return
		}
		if r.Method == http.MethodGet && (r.ContentLength != 0 || len(r.TransferEncoding) != 0) {
			write(w, 400, Error{Message: "GET body not supported"})
			return
		}
		mux.ServeHTTP(w, r)
	}), nil
}

func (s *Server) association(w http.ResponseWriter, r *http.Request, slaveRequest bool) (core.Association, bool) {
	caller, _ := security.SAEIdentity(r, s.identities)
	a := core.Association{Master: caller, Slave: r.PathValue("sae")}
	if slaveRequest {
		a = core.Association{Master: r.PathValue("sae"), Slave: caller}
	}
	if !s.allowed[a] {
		write(w, 401, Error{Message: "unauthorized"})
		return a, false
	}
	return a, true
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	a, ok := s.association(w, r, false)
	if !ok {
		return
	}
	if _, err := query(r); err != nil {
		fail(w, err)
		return
	}
	i := s.repo.Inventory(a)
	write(w, 200, Status{SourceKMEID: s.kme, TargetKMEID: s.kme, MasterSAEID: a.Master, SlaveSAEID: a.Slave, KeySize: core.KeyBits, StoredKeyCount: i.Available, MaxKeyCount: i.Capacity, MaxKeyPerRequest: core.MaxBatch, MaxKeySize: core.KeyBits, MinKeySize: core.KeyBits})
}

func (s *Server) enc(w http.ResponseWriter, r *http.Request) {
	a, ok := s.association(w, r, false)
	if !ok {
		return
	}
	var req KeyRequest
	if r.Method == http.MethodPost {
		if _, err := query(r); err != nil {
			fail(w, err)
			return
		}
		if err := readJSON(w, r, &req, "number", "size", "additional_slave_SAE_IDs", "extension_mandatory", "extension_optional"); err != nil {
			fail(w, err)
			return
		}
	} else {
		q, err := query(r, "number", "size")
		if err != nil {
			fail(w, err)
			return
		}
		for name, values := range q {
			n, err := strconv.Atoi(values[0])
			if err != nil {
				fail(w, core.ErrInvalid)
				return
			}
			if name == "number" {
				req.Number = &n
			} else {
				req.Size = &n
			}
		}
	}
	count, size := 1, core.KeyBits
	if req.Number != nil {
		count = *req.Number
	}
	if req.Size != nil {
		size = *req.Size
	}
	if size%8 != 0 {
		fail(w, requestError{400, "size shall be a multiple of 8"})
		return
	}
	if len(req.Mandatory) > 0 {
		fail(w, requestError{400, "not all extension_mandatory parameters are supported"})
		return
	}
	for _, extension := range req.Optional {
		if extension == nil {
			fail(w, core.ErrInvalid)
			return
		}
	}
	if count < 1 || count > core.MaxBatch || size != core.KeyBits || len(req.AdditionalSlaveSAEIDs) > 0 {
		fail(w, core.ErrInvalid)
		return
	}
	res, err := s.repo.ReserveKeys(a, count)
	if err != nil {
		fail(w, err)
		return
	}
	keys, err := s.repo.ConsumeReservation(a, res.Token)
	if err != nil {
		fail(w, err)
		return
	}
	deliver(w, keys)
}

func (s *Server) dec(w http.ResponseWriter, r *http.Request) {
	a, ok := s.association(w, r, true)
	if !ok {
		return
	}
	var req KeyIDs
	if r.Method == http.MethodPost {
		if _, err := query(r); err != nil {
			fail(w, err)
			return
		}
		if err := readJSON(w, r, &req, "key_IDs"); err != nil {
			fail(w, err)
			return
		}
	} else {
		q, err := query(r, "key_ID")
		if err != nil {
			fail(w, err)
			return
		}
		req.IDs = []KeyID{{ID: q.Get("key_ID")}}
	}
	ids := make([]core.KeyID, len(req.IDs))
	for i, id := range req.IDs {
		ids[i] = core.KeyID(id.ID)
	}
	keys, err := s.repo.ConsumePeerKeys(a, ids)
	if err != nil {
		fail(w, err)
		return
	}
	deliver(w, keys)
}

func deliver(w http.ResponseWriter, keys []core.Delivery) {
	container := KeyContainer{Keys: make([]KeyValue, len(keys))}
	for i := range keys {
		container.Keys[i] = KeyValue{ID: string(keys[i].ID), Key: base64.StdEncoding.EncodeToString(keys[i].Material)}
		clear(keys[i].Material)
	}
	// Consumption has committed. A write failure must never roll it back.
	write(w, 200, container)
}

func fail(w http.ResponseWriter, err error) {
	status, message := 503, "key material unavailable"
	var re requestError
	switch {
	case errors.As(err, &re):
		status, message = re.status, re.message
	case errors.Is(err, core.ErrInvalid):
		status, message = 400, "invalid key request"
	case errors.Is(err, core.ErrUnauthorized):
		status, message = 401, "unauthorized"
	}
	write(w, status, Error{Message: message})
}

func write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
