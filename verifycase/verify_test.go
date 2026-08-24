package verifycase

import (
	"os"
	"testing"

	"certbridge/internal/crl"
	"certbridge/internal/store"
)

func TestCrlVersionAdvancesAfterEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(dir+"/revocations.json", 0o755); err != nil {
		t.Fatal(err)
	}
	state := store.NewState(dir)
	svc := crl.NewService(state)
	entry := store.RevocationEntry{Serial: 1, Reason: "unspecified", Generation: 1}
	if err := svc.Append(entry); err == nil {
		t.Fatal("append must fail when the revocations file is blocked")
	}
	if got := svc.Version(); got != 0 {
		t.Fatalf("version advanced although entries were not durable: %d", got)
	}
}
