package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/security"
)

func main() {
	mode := flag.String("mode", "", "csr or validate")
	out := flag.String("out", "", "new credential generation directory")
	identity := flag.String("identity", "", "exact URI SAN identity")
	dns := flag.String("dns", "", "comma-separated DNS SANs")
	ip := flag.String("ip", "", "comma-separated IP SANs")
	cert := flag.String("cert", "", "issued certificate chain")
	key := flag.String("key", "", "private key file")
	ca := flag.String("ca", "", "trusted CA bundle")
	crls := flag.String("crls", "", "comma-separated full CRL files")
	host := flag.String("hostname", "", "expected server hostname")
	server := flag.Bool("server", false, "validate serverAuth rather than clientAuth")
	flag.Parse()
	var err error
	switch *mode {
	case "csr":
		var names []string
		var ips []net.IP
		if *dns != "" {
			names = strings.Split(*dns, ",")
		}
		if *ip != "" {
			for _, s := range strings.Split(*ip, ",") {
				p := net.ParseIP(s)
				if p == nil {
					fmt.Fprintln(os.Stderr, "invalid IP SAN")
					os.Exit(1)
				}
				ips = append(ips, p)
			}
		}
		err = security.CreateCSR(*out, *identity, names, ips)
	case "validate":
		err = security.ValidateCredential(*cert, *key, *ca, *identity, *host, *server, strings.Split(*crls, ","))
	default:
		err = fmt.Errorf("choose csr or validate")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "credential operation failed")
		os.Exit(1)
	}
	fmt.Println("credential operation completed")
}
