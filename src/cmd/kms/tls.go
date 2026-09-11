package main

import "crypto/tls"

func loadServerCertificate(c *tls.Config, certPath, keyPath string) error {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}
	c.Certificates = []tls.Certificate{cert}
	return nil
}
