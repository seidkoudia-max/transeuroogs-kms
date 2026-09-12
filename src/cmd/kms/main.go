package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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
	"slices"
	"syscall"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/allocation"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/config"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/etsi014"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/etsi020"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/ingest"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metadata"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metapi"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/peering"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/postgres"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/relay"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/sdnapi"
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
	certName := flag.String("certificate-name", "kms", "certificate/key filename stem in PKI directory")
	labSummary := flag.Bool("lab-summary", false, "emit material-free network laboratory summary on shutdown")
	count := flag.Int("synthetic-keys", 0, "opt-in synthetic keys for the first configured association")
	ttl := flag.Duration("synthetic-ttl", time.Hour, "synthetic key lifetime")
	initialize := flag.Bool("initialize-state", false, "explicitly provision a fresh operational state namespace")
	migrate := flag.Bool("migrate-database", false, "apply database schema with a separate migration credential and exit")
	flag.Parse()
	c, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *count < 0 || *count > c.Capacity || *ttl <= 0 {
		return fmt.Errorf("invalid synthetic provisioning parameters")
	}
	memory, err := storage.NewMemory(c.Capacity, nil)
	if err != nil {
		return err
	}
	var repo core.Repository = memory
	var pg *postgres.Store
	var managed durable.Store
	var history *metadata.Store
	var recovered []byte
	var policy *allocation.Setup
	if c.SDN != nil {
		policy = &allocation.Setup{Config: *c.SDN, Issuer: c.Metadata.Issuer, ClockUncertaintyMS: c.Metadata.ClockUncertaintyMS}
	}
	if *migrate {
		if c.Operational == nil {
			return fmt.Errorf("operational configuration required")
		}
		return postgres.Migrate(c.Operational.Database)
	}
	if *initialize && c.Operational == nil {
		return fmt.Errorf("operational configuration required")
	}
	if c.Operational != nil {
		pg, recovered, err = postgres.Open(c.Operational.Database, *initialize)
		if err != nil {
			return err
		}
		defer pg.Close()
		managed = pg
		defer clear(recovered)
		if *count > 0 && recovered != nil {
			return fmt.Errorf("synthetic provisioning requires a fresh operational namespace")
		}
	}
	if c.Metadata != nil {
		project := metadata.Projector(storage.ProjectMetadata)
		dir, context := c.Metadata.StateDir, "transeuroogs-local-metadata-v1"
		if c.Eagle != nil {
			project = ingest.ProjectMetadata(*c.Eagle, c.Associations[0])
			dir = c.Eagle.StateDir
			context = "transeuroogs-segmented-ingestion-v1"
		}
		if c.InterKMS != nil {
			project = relay.ProjectMetadata(*c.InterKMS)
			dir = c.InterKMS.StateDir
			context = "transeuroogs-relay-state-v1"
		}
		if managed == nil {
			managed, recovered, err = durable.Open(dir, context)
			if err != nil {
				return err
			}
			defer managed.Close()
		}
		if *count > 0 && recovered != nil {
			return fmt.Errorf("synthetic provisioning requires fresh metadata state")
		}
		signing, e := metadata.LoadSigning(c.Metadata.SigningKeyFile, c.Metadata.CredentialID)
		if e != nil {
			return e
		}
		history, recovered, err = metadata.Open(*c.Metadata, signing, managed, recovered, project, nil)
		if err != nil {
			return err
		}
		managed = history
		defer history.Close()
	}
	if managed != nil && c.Eagle == nil && c.InterKMS == nil {
		binding, _ := json.Marshal(struct {
			KME        string
			Pairs      []core.Association
			Identities map[string]string
			Local      []string
		}{c.KMEID, c.Associations, c.Identities, c.LocalSAEs})
		hash := sha256.Sum256(binding)
		persistent, e := storage.OpenPersistent(c.Capacity, hex.EncodeToString(hash[:]), managed, recovered, policy)
		if e != nil {
			return e
		}
		defer persistent.Close()
		repo = persistent
	}
	var engine *relay.Engine
	var ingestion *ingest.Repository
	if c.Eagle != nil {
		if *count != 0 {
			return fmt.Errorf("segmented mode accepts keys only from the configured synthetic upstream service")
		}
		u := c.Eagle
		cert, e := tls.LoadX509KeyPair(filepath.Join(u.PKIDir, u.CertificateName+".crt.pem"), filepath.Join(u.PKIDir, u.CertificateName+".key.pem"))
		if e != nil {
			return e
		}
		ca, e := os.ReadFile(filepath.Join(u.PKIDir, "ca.crt.pem"))
		if e != nil {
			return e
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return fmt.Errorf("invalid upstream CA")
		}
		tc := &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}}
		if c.Operational != nil {
			security.RequireCRLs(tc, c.Operational.UpstreamCRLFiles)
		}
		client, e := etsi014.NewClient(*u, tc)
		if e != nil {
			return e
		}
		defer client.Close()
		if managed != nil {
			ingestion, e = ingest.OpenStore(*u, c.Associations[0], c.Capacity, client, managed, recovered, policy)
		} else {
			ingestion, e = ingest.Open(*u, c.Associations[0], c.Capacity, client)
		}
		if e != nil {
			return e
		}
		defer ingestion.Close()
		repo = ingestion
	}
	if c.InterKMS != nil {
		cert, e := tls.LoadX509KeyPair(filepath.Join(*pki, *certName+".crt.pem"), filepath.Join(*pki, *certName+".key.pem"))
		if e != nil {
			return e
		}
		leaf, e := x509.ParseCertificate(cert.Certificate[0])
		if e != nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != c.InterKMS.Identity {
			return fmt.Errorf("KME certificate identity does not match configuration")
		}
		ca, e := os.ReadFile(filepath.Join(*pki, "ca.crt.pem"))
		if e != nil {
			return e
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return fmt.Errorf("invalid peer CA")
		}
		tc := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert}}
		if c.Operational != nil {
			security.RequireCRLs(tc, c.Operational.CRLFiles)
		}
		client, e := etsi020.NewClient(*c.InterKMS, tc)
		if e != nil {
			return e
		}
		defer client.Close()
		if managed != nil {
			engine, e = relay.OpenStore(*c.InterKMS, c.Associations, c.Capacity, client, managed, recovered, policy)
		} else {
			engine, e = relay.Open(*c.InterKMS, c.Associations, c.Capacity, client)
		}
		if e != nil {
			return e
		}
		defer engine.Close()
		if *labSummary {
			defer func() {
				_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"event": "network_summary", "kme_id": c.KMEID, "summary": engine.Snapshot()})
			}()
		}
		repo = engine
		if *count > 0 && engine.Snapshot().Records > 0 {
			return fmt.Errorf("synthetic provisioning requires a fresh network state directory; restart with --synthetic-keys=0")
		}
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
	if engine != nil {
		mux := http.NewServeMux()
		mux.Handle("/", handler)
		mux.Handle("/kmapi/", etsi020.Handler(engine, *c.InterKMS, peering.Standard))
		mux.Handle("/lab/", etsi020.Handler(engine, *c.InterKMS, peering.LabRelay))
		handler = mux
	}
	if history != nil {
		apps := map[string]string{}
		locals := c.LocalSAEs
		if c.InterKMS != nil {
			locals = c.InterKMS.LocalSAEs
		}
		for uri, sae := range c.Identities {
			if (c.InterKMS == nil && len(locals) == 0) || slices.Contains(locals, sae) {
				apps[uri] = sae
			}
		}
		mux := http.NewServeMux()
		mux.Handle("/", handler)
		mux.Handle("/metadata/", metapi.New(history, apps, c.Associations, c.Metadata.Readers))
		handler = mux
	}
	if c.SDN != nil {
		manager, ok := repo.(allocation.Manager)
		if !ok {
			return fmt.Errorf("repository does not support management")
		}
		agent := sdnapi.New(manager, *c.SDN, c.Identities)
		mux := http.NewServeMux()
		mux.Handle("/", handler)
		mux.Handle("/management/", agent)
		mux.Handle("/restconf/", agent)
		handler = mux
	}
	if c.Operational != nil {
		ids := []string{}
		if c.SDN != nil {
			for id := range c.SDN.Principals {
				ids = append(ids, id)
			}
		}
		for id := range c.Identities {
			ids = append(ids, id)
		}
		if c.Metadata != nil {
			for id := range c.Metadata.Readers {
				ids = append(ids, id)
			}
		}
		if c.InterKMS != nil {
			for _, peer := range c.InterKMS.Peers {
				ids = append(ids, peer.Identity)
			}
		}
		handler, err = security.Guard(handler, ids, c.Operational.Limits, c.Operational.CRLFiles, pg)
		if err != nil {
			return err
		}
	}
	tlsConfig, err := security.ServerTLS(filepath.Join(*pki, "ca.crt.pem"))
	if err != nil {
		return err
	}
	if c.Operational != nil {
		security.RequireCRLs(tlsConfig, c.Operational.CRLFiles)
	}
	server := &http.Server{Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	// Validate the certificate before reporting readiness.
	certPath, keyPath := filepath.Join(*pki, *certName+".crt.pem"), filepath.Join(*pki, *certName+".key.pem")
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
	if ingestion != nil {
		workerCtx, cancel := context.WithCancel(ctx)
		finished := make(chan struct{})
		go func() { defer close(finished); ingestion.Run(workerCtx) }()
		defer func() { cancel(); <-finished }()
	}
	if engine != nil {
		workerCtx, cancel := context.WithCancel(ctx)
		finished := make(chan struct{})
		go func() { defer close(finished); engine.Run(workerCtx) }()
		defer func() { cancel(); <-finished }()
	}
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
