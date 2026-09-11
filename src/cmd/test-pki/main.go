package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/seidkoudia-max/transeuroogs-kms/src/internal/testpki"
)

func main() {
	out := flag.String("out", ".local/pki", "directory for synthetic laboratory certificates (replaces existing test files)")
	flag.Parse()
	p, err := testpki.Generate(time.Now())
	if err != nil {
		log.Fatal(err)
	}
	if err := p.Write(*out); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Generated 24-hour TEST certificates. CA private key was not persisted.")
}
