package verifycase

import (
	"testing"

	"certbridge/internal/crl"
	"certbridge/internal/store"
)

func TestCrlPublishHoldsVersionOnPartialFailure(t *testing.T) {
	state := store.NewState(t.TempDir())
	svc := crl.NewService(state)
	nodes := []crl.DistributionNode{{ID: "n1"}, {ID: "n2"}, {ID: "n3"}}
	if err := svc.Publish(nodes, "n2"); err == nil {
		t.Fatal("publish must fail when a node fails")
	}
	if got := svc.Version(); got != 0 {
		t.Fatalf("version advanced on partial failure: %d", got)
	}
}
