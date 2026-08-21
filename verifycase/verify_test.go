package verifycase

import (
	"os"
	"path/filepath"
	"testing"

	"certbridge/internal/audit"
	"certbridge/internal/keyarch"
	"certbridge/internal/store"
)

func TestArchiveRestoreWritesBeforeMarking(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	state := store.NewState(t.TempDir())
	sink := audit.NewSink(state)
	archiver := keyarch.NewArchiver(blocker, state, sink)
	if err := archiver.Restore("c1", []byte("abcdefgh")); err == nil {
		t.Fatal("restore must fail on an invalid root")
	}
	if record, ok := state.Key("c1"); ok && record.Status == "restored" {
		t.Fatal("restore marked restored although material was not written")
	}
}
