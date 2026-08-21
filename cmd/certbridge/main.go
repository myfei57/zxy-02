// Command certbridge runs the CertBridge PKI/CA service.
package main

import (
	"flag"
	"log"
	"net/http"

	"certbridge/internal/audit"
	"certbridge/internal/console"
	"certbridge/internal/crl"
	"certbridge/internal/enrollment"
	"certbridge/internal/issuer"
	"certbridge/internal/keyarch"
	"certbridge/internal/revocation"
	"certbridge/internal/store"
	"certbridge/internal/verify"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	dataDir := flag.String("data", "data", "data directory")
	flag.Parse()

	state := store.NewState(*dataDir)
	if err := state.Load(); err != nil {
		log.Fatalf("load state: %v", err)
	}
	pool := issuer.NewSerialPool(1000)
	issuerSvc := issuer.NewIssuer(state, pool)
	crlSvc := crl.NewService(state)
	cache := verify.NewCache()
	verifier := verify.NewVerifier(state, cache)
	revoker := revocation.NewService(state, crlSvc, cache)
	auditSink := audit.NewSink(state)
	archiver := keyarch.NewArchiver(*dataDir, state, auditSink)
	windows := enrollment.NewWindowManager(state)
	api := console.NewAPI(state, issuerSvc, revoker, crlSvc, verifier, archiver, windows, auditSink, pool)

	log.Printf("CertBridge listening on %s (data: %s)", *addr, *dataDir)
	if err := http.ListenAndServe(*addr, api.Router()); err != nil {
		log.Fatal(err)
	}
}
