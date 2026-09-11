// A disposable synthetic black-box service, exposing two local 014 interfaces.
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
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/synthetic"
)

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "synthetic EAGLE service failed; no key data displayed")
		os.Exit(1)
	}
}
func run() error {
	pki := flag.String("pki-dir", ".local/pki", "synthetic SES test PKI")
	count := flag.Int("synthetic-keys", 0, "explicit synthetic inventory (required)")
	delay := flag.Duration("ready-delay", time.Second, "delay modelling final-key availability")
	ttl := flag.Duration("synthetic-ttl", time.Hour, "synthetic provider key lifetime")
	flag.Parse()
	if *count < 1 || *count > 100000 || *delay < 0 || *ttl <= *delay {
		return core.ErrInvalid
	}
	pair := core.Association{Master: "GW-LU", Slave: "GW-GR"}
	memory, err := storage.NewMemory(*count, nil)
	if err != nil {
		return err
	}
	if err = synthetic.Seed(memory, pair, *count, time.Now(), *ttl); err != nil {
		return err
	}
	repo := &eaglelab.Delayed{Repository: memory, ReadyAt: time.Now().Add(*delay)}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	failures := make(chan error, 2)
	addresses := map[string]string{}
	for _, site := range []struct{ name, kme, local string }{{"eagle-lu", "SES-LU", "GW-LU"}, {"eagle-gr", "SES-GR", "GW-GR"}} {
		c := config.Config{KMEID: site.kme, Capacity: *count, Identities: map[string]string{"urn:transeuroogs:kme:lu": "GW-LU", "urn:transeuroogs:kme:gr": "GW-GR"}, LocalSAEs: []string{site.local}, Associations: []core.Association{pair}, TargetKMEs: map[string]string{"GW-LU": "SES-LU", "GW-GR": "SES-GR"}}
		handler, e := etsi014.New(repo, c)
		if e != nil {
			return e
		}
		tc, e := security.ServerTLS(filepath.Join(*pki, "ca.crt.pem"))
		if e != nil {
			return e
		}
		cert, e := tls.LoadX509KeyPair(filepath.Join(*pki, site.name+".crt.pem"), filepath.Join(*pki, site.name+".key.pem"))
		if e != nil {
			return e
		}
		tc.Certificates = []tls.Certificate{cert}
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			return e
		}
		server := &http.Server{Handler: handler, TLSConfig: tc, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16384}
		defer server.Close()
		addresses[site.local] = "https://" + listener.Addr().String()
		go func() { failures <- server.ServeTLS(listener, "", "") }()
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"event": "listening", "services": addresses, "synthetic_keys": *count})
	select {
	case <-ctx.Done():
		return nil
	case err := <-failures:
		return err
	}
}
