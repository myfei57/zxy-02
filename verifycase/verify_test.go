package verifycase

import (
	"testing"

	"certbridge/internal/crl"
	"certbridge/internal/enrollment"
	"certbridge/internal/issuer"
	"certbridge/internal/revocation"
	"certbridge/internal/store"
	"certbridge/internal/verify"
)

func TestRevokedCertificateNeverPassesCachedVerify(t *testing.T) {
	state := store.NewState(t.TempDir())
	svc := issuer.NewIssuer(state, issuer.NewSerialPool(1000))
	reqID, err := enrollment.Submit(state, []byte("csr"))
	if err != nil {
		t.Fatal(err)
	}
	_ = enrollment.Approve(state, reqID)
	cert, err := svc.Issue(reqID)
	if err != nil {
		t.Fatal(err)
	}
	cache := verify.NewCache()
	verifier := verify.NewVerifier(state, cache)
	if ok, _ := verifier.Verify(cert.ID); !ok {
		t.Fatal("active cert must verify")
	}
	revoker := revocation.NewService(state, crl.NewService(state), cache)
	if err := revoker.RevokeCertificate(cert.ID, "key_compromise"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := verifier.Verify(cert.ID); ok {
		t.Fatal("revoked certificate must not pass verification")
	}
}
