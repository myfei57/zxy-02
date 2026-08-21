package verifycase

import (
	"testing"

	"certbridge/internal/enrollment"
	"certbridge/internal/issuer"
	"certbridge/internal/store"
)

func TestIssueUsesApprovedSnapshot(t *testing.T) {
	state := store.NewState(t.TempDir())
	reqID, err := enrollment.Submit(state, []byte("original-csr"))
	if err != nil {
		t.Fatal(err)
	}
	if err := enrollment.Approve(state, reqID); err != nil {
		t.Fatal(err)
	}
	req, _ := state.Request(reqID)
	req.Raw = []byte("tampered-csr")
	state.PutRequest(req)
	svc := issuer.NewIssuer(state, issuer.NewSerialPool(1000))
	cert, err := svc.Issue(reqID)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := state.Request(reqID)
	if cert.Subject != want.Snapshot.Subject {
		t.Fatalf("issuance did not use the approved snapshot: got %q want %q", cert.Subject, want.Snapshot.Subject)
	}
}
