package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/config"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/etsi014"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/security"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/storage"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/synthetic"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "deploy/config/local.json", "KMS configuration")
	listen := flag.String("listen", "127.0.0.1:8443", "TLS listen address")
	pki := flag.String("pki-dir", ".local/pki", "directory containing ca.crt.pem and kms certificate/key")
	count := flag.Int("synthetic-keys", 0, "opt-in synthetic keys for the first configured association")
	ttl := flag.Duration("synthetic-ttl", time.Hour, "synthetic key lifetime")
	flag.Parse()
	c, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *count < 0 || *count > c.Capacity || *ttl <= 0 {
		return fmt.Errorf("invalid synthetic provisioning parameters")
	}
	repo, err := storage.NewMemory(c.Capacity, nil)
	if err != nil {
		return err
	}
	if *count > 0 {
		if err := synthetic.Seed(repo, c.Associations[0], *count, time.Now(), *ttl); err != nil {
			return err
		}
	}
	handler, err := etsi014.New(repo, c)
	if err != nil {
		return err
	}
	tlsConfig, err := security.ServerTLS(filepath.Join(*pki, "ca.crt.pem"))
	if err != nil {
		return err
	}
	server := &http.Server{Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	// Validate the certificate before reporting readiness.
	certPath, keyPath := filepath.Join(*pki, "kms.crt.pem"), filepath.Join(*pki, "kms.key.pem")
	if err := loadServerCertificate(tlsConfig, certPath, keyPath); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"event": "listening", "address": listener.Addr().String(), "kme_id": c.KMEID, "synthetic_keys": *count})
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
