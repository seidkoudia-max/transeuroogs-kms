// kms-metadata provisions separate laboratory signing credentials and verifies
// authorised offline evidence exports. It never contacts a key service.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/metadata"
)

func main() {
	if run(os.Args[1:]) != nil {
		fmt.Fprintln(os.Stderr, "Metadata operation failed; no key material displayed.")
		os.Exit(1)
	}
}
func read(path string, out any, max int64) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, max+1))
	d.DisallowUnknownFields()
	if e = d.Decode(out); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return metadata.ErrEvidence
	}
	return nil
}
func exclusive(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	return closeErr
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("command required")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "keygen":
		private := f.String("private", "", "new PKCS#8 private credential file")
		public := f.String("public", "", "new PKIX public verification file")
		if f.Parse(args[1:]) != nil || *private == "" || *public == "" || *private == *public || f.NArg() != 0 {
			return metadata.ErrEvidence
		}
		// Never overwrite an established signing identity.
		for _, p := range []string{*private, *public} {
			if _, e := os.Lstat(p); !os.IsNotExist(e) {
				return metadata.ErrEvidence
			}
		}
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return e
		}
		der, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return e
		}
		defer clear(der)
		encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		defer clear(encoded)
		pub, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if e != nil {
			return e
		}
		if e = exclusive(*private, encoded); e != nil {
			return e
		}
		return exclusive(*public, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
	case "trace":
		trustFile := f.String("trust", "", "issuer allowlist JSON")
		queryFile := f.String("query", "", "incident query JSON")
		pagesFile := f.String("evidence", "", "signed-page NDJSON export")
		audience := f.String("audience", "", "expected evidence audience")
		out := f.String("out", "", "new output report file")
		if f.Parse(args[1:]) != nil || *out == "" || f.NArg() != 0 {
			return metadata.ErrEvidence
		}
		var trust []metadata.Trust
		var query metadata.Query
		if read(*trustFile, &trust, 1<<20) != nil || read(*queryFile, &query, 8192) != nil {
			return metadata.ErrEvidence
		}
		in, e := os.Open(*pagesFile)
		if e != nil {
			return e
		}
		defer in.Close()
		scanner := bufio.NewScanner(io.LimitReader(in, (64<<20)+1))
		scanner.Buffer(make([]byte, 4096), 128<<10)
		pages := []metadata.SignedPage{}
		total := 0
		for scanner.Scan() {
			total += len(scanner.Bytes()) + 1
			if total > 64<<20 || len(pages) >= 10000 {
				return metadata.ErrEvidence
			}
			var p metadata.SignedPage
			if json.Unmarshal(scanner.Bytes(), &p) != nil {
				return metadata.ErrEvidence
			}
			pages = append(pages, p)
		}
		if scanner.Err() != nil {
			return metadata.ErrEvidence
		}
		events, coverage, e := metadata.VerifyPages(pages, trust, *audience)
		if e != nil {
			return e
		}
		report, e := metadata.Trace(query, events, coverage)
		if e != nil {
			return e
		}
		b, e := json.MarshalIndent(report, "", "  ")
		if e != nil {
			return e
		}
		b = append(b, '\n')
		return exclusive(*out, b)
	default:
		return metadata.ErrEvidence
	}
}
