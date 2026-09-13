// Disposable, loopback-only synthetic 014 source for physically budgeted fibers.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/config"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/eaglelab"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/etsi014"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/security"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/storage"
)

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "Synthetic physical source failed; no key data displayed")
		os.Exit(1)
	}
}

func run() error {
	pki := flag.String("pki-dir", "", "synthetic services test PKI")
	permitPath := flag.String("permit", "", "physical capacity permit")
	state := flag.String("state-dir", "", "retained spent-permit directory")
	speed := flag.Float64("simulation-speed", 1, "simulated seconds per wall second")
	clockFile := flag.String("clock-file", "", "optional common laboratory clock barrier file")
	flag.Parse()
	p, delay, err := eaglelab.ReadPhysicalPermit(*permitPath, *speed)
	if err != nil {
		return err
	}
	name, master, slave := "", "", ""
	switch p.LinkID {
	case "fiber-windhof-jfk":
		name, master, slave = "link-lux", "jfk", "windhof"
	case "fiber-helmos-hellas":
		name, master, slave = "link-hellas", "helmos", "hellas"
	case "eagle-offline-windhof-helmos":
		name, master, slave = "eagle-pair", "windhof", "helmos"
	default:
		return core.ErrInvalid
	}
	if delay >= time.Hour || *pki == "" {
		return core.ErrInvalid
	}
	if err := eaglelab.ClaimPhysicalPermit(*state, p); err != nil {
		return err
	}
	pair := core.Association{Master: "LINK-MASTER", Slave: "LINK-SLAVE"}
	memory, err := storage.NewMemory(max(1, p.Count), nil)
	if err != nil {
		return err
	}
	cfg := config.Config{KMEID: name, Capacity: max(1, p.Count), Associations: []core.Association{pair},
		Identities: map[string]string{"urn:transeuroogs:kme:" + master: pair.Master, "urn:transeuroogs:kme:" + slave: pair.Slave}}
	handler, err := etsi014.New(memory, cfg)
	if err != nil {
		return err
	}
	tc, err := security.ServerTLS(filepath.Join(*pki, "ca.crt.pem"))
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(*pki, name+".crt.pem"), filepath.Join(*pki, name+".key.pem"))
	if err != nil {
		return err
	}
	tc.Certificates = []tls.Certificate{cert}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	server := &http.Server{Handler: handler, TLSConfig: tc, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16384}
	defer server.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	supply := make(chan error, 1)
	go func() {
		start := time.Now()
		if *clockFile != "" {
			var err error
			start, err = eaglelab.WaitPhysicalClock(ctx, *clockFile)
			if err != nil {
				supply <- err
				return
			}
		}
		supply <- <-eaglelab.SupplyPhysicalAt(ctx, memory, pair, p, *speed, start)
	}()
	fail := make(chan error, 1)
	go func() { fail <- server.ServeTLS(listener, "", "") }()
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"event": "listening", "address": listener.Addr().String(), "synthetic": true, "link_id": p.LinkID}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-supply:
		return err
	case err := <-fail:
		return err
	}
}
