package verifycase

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"certbridge/internal/audit"
	"certbridge/internal/keyarch"
	"certbridge/internal/store"
)

func TestKeyArchiveFailureNeverLeaksToAudit(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	state := store.NewState(t.TempDir())
	sink := audit.NewSink(state)
	archiver := keyarch.NewArchiver(blocker, state, sink)
	material := []byte("abcdefgh")
	if err := archiver.Archive("cert-1", material); err == nil {
		t.Fatal("archive must fail on an invalid root")
	}
	for _, entry := range state.Audit() {
		if strings.Contains(entry.Detail, string(material)) {
			t.Fatal("audit log contains key material")
		}
	}
}
