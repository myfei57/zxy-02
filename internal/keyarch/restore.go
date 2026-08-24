package keyarch

import (
	"fmt"
	"path/filepath"

	"certbridge/internal/store"
)

// Restore writes the key material back durably and only then marks the
// restoration complete.
func (a *Archiver) Restore(certID string, material []byte) error {
	path := filepath.Join(a.root, "keys", certID+".key")
	if err := store.WriteFileAtomic(path, material); err != nil {
		return fmt.Errorf("restore key %s: %w", certID, err)
	}
	a.state.PutKey(&store.KeyRecord{CertID: certID, Status: "restored"})
	a.audit.Record("key_restored", "cert="+certID)
	return nil
}
