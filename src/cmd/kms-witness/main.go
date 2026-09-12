package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/security"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/witness"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Run this on independent trusted infrastructure with separate retention and
// administration. Co-locating it with the KMS is a synthetic recovery test only.
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "checkpoint authority unavailable")
		os.Exit(1)
	}
}
func run() error {
	path := flag.String("config", "", "witness configuration")
	initialize := flag.Bool("initialize", false, "explicitly initialize a new witness namespace store")
	flag.Parse()
	var c struct {
		StateDir        string              `json:"state_dir"`
		Listen          string              `json:"listen"`
		CAFile          string              `json:"ca_file"`
		CertificateFile string              `json:"certificate_file"`
		KeyFile         string              `json:"key_file"`
		CRLFiles        []string            `json:"crl_files"`
		Grants          map[string][]string `json:"grants"`
	}
	f, e := os.Open(*path)
	if e != nil {
		return e
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 65537))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil || len(c.Grants) == 0 || len(c.CRLFiles) == 0 || c.Listen == "" || c.StateDir == "" {
		return durable.ErrState
	}
	_, e = os.Stat(filepath.Join(c.StateDir, "state.enc"))
	if e != nil && !*initialize {
		return durable.ErrState
	}
	if e == nil && *initialize {
		return durable.ErrState
	}
	j, raw, e := durable.Open(c.StateDir, "transeuroogs-witness-v1")
	if e != nil {
		return e
	}
	defer j.Close()
	a, e := witness.Open(j, raw)
	if e != nil {
		return e
	}
	defer a.Close()
	tc, e := security.ServerTLS(c.CAFile)
	if e != nil {
		return e
	}
	security.RequireCRLs(tc, c.CRLFiles)
	s := &http.Server{Addr: c.Listen, Handler: witness.LiveHandler(a, c.Grants, c.CRLFiles), TLSConfig: tc, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192}
	return s.ListenAndServeTLS(c.CertificateFile, c.KeyFile)
}
