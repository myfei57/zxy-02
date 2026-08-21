package verifycase

import (
	"testing"

	"certbridge/internal/crl"
	"certbridge/internal/enrollment"
	"certbridge/internal/issuer"
	"certbridge/internal/revocation"
	"certbridge/internal/store"
)

func TestRenewalRevokesCorrectGeneration(t *testing.T) {
	state := store.NewState(t.TempDir())
	svc := issuer.NewIssuer(state, issuer.NewSerialPool(1000))
	reqID, err := enrollment.Submit(state, []byte("csr-data"))
	if err != nil {
		t.Fatal(err)
	}
	_ = enrollment.Approve(state, reqID)
	cert, err := svc.Issue(reqID)
	if err != nil {
		t.Fatal(err)
	}
	crlSvc := crl.NewService(state)
	_ = revocation.NewService(state, crlSvc, nil)
	windows := enrollment.NewWindowManager(state)
	renewed, err := windows.RenewCertificate(cert.ID, func(gen int64) (*store.Certificate, error) {
		return svc.IssueFromSnapshot(store.RequestSnapshot{Subject: cert.Subject, SANs: cert.SANs}, gen)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range state.Revocations() {
		if entry.Serial == renewed.Serial {
			t.Fatal("renewal must not revoke the new generation")
		}
	}
}
