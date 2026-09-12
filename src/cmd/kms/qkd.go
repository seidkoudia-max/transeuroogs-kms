package main

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/config"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/core"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/durable"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/etsi014"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/peering"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/qkdrelay"
	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/security"
	"os"
	"path/filepath"
)

func openQKD(c config.Config) (*qkdrelay.Bridge, func(), error) {
	clients := []*etsi014.Client{}
	closeClients := func() {
		for _, client := range clients {
			client.Close()
		}
	}
	providers := map[string]qkdrelay.Provider{}
	for id, p := range c.InterKMS.Peers {
		if p.Mode != peering.QKDRelay {
			continue
		}
		u := p.Link
		cert, e := tls.LoadX509KeyPair(filepath.Join(u.PKIDir, u.CertificateName+".crt.pem"), filepath.Join(u.PKIDir, u.CertificateName+".key.pem"))
		if e != nil {
			closeClients()
			return nil, nil, core.ErrInvalid
		}
		pem, e := os.ReadFile(filepath.Join(u.PKIDir, "ca.crt.pem"))
		roots := x509.NewCertPool()
		if e != nil || !roots.AppendCertsFromPEM(pem) {
			closeClients()
			return nil, nil, core.ErrInvalid
		}
		tc := &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}}
		if c.Operational != nil {
			security.RequireCRLs(tc, c.Operational.UpstreamCRLFiles)
		}
		client, e := etsi014.NewClient(*u, tc)
		if e != nil {
			closeClients()
			return nil, nil, e
		}
		clients = append(clients, client)
		providers[id] = client
	}
	j, raw, e := durable.Open(c.InterKMS.QKDStateDir, qkdrelay.Profile)
	if e != nil {
		closeClients()
		return nil, nil, e
	}
	b, e := qkdrelay.Open(*c.InterKMS, providers, c.Capacity, j, raw)
	if e != nil {
		j.Close()
		closeClients()
		return nil, nil, e
	}
	return b, func() { b.Close(); closeClients() }, nil
}
