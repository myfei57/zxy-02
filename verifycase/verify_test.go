package verifycase

import (
	"testing"

	"certbridge/internal/revocation"
	"certbridge/internal/store"
)

func TestRevocationReasonSurvivesTransition(t *testing.T) {
	cert := &store.Certificate{ID: "c1", Serial: 1, Generation: 1, Status: store.StatusActive}
	if err := revocation.Transition(cert, "key_compromise"); err != nil {
		t.Fatal(err)
	}
	if cert.Reason != "key_compromise" {
		t.Fatalf("revocation reason lost: got %q", cert.Reason)
	}
}
