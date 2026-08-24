package verifycase

import (
	"testing"

	"certbridge/internal/enrollment"
	"certbridge/internal/store"
)

func TestRenewalWindowExcludesDowntime(t *testing.T) {
	state := store.NewState(t.TempDir())
	state.PutWindow(&store.RenewalWindow{CertID: "c1", OpensAt: 100, ClosesAt: 200, Elapsed: 100})
	m := enrollment.NewWindowManager(state)
	m.Recover("c1", 10)
	w, _ := state.Window("c1")
	if w.Elapsed != 100 {
		t.Fatalf("downtime must not count as business elapsed: got %d", w.Elapsed)
	}
}
