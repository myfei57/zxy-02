// Package keyarch archives and restores private key material with strict
// separation from the audit trail.
package keyarch

import (
	"errors"
	"fmt"
	"path/filepath"

	"certbridge/internal/audit"
	"certbridge/internal/store"
)

// ErrKeyMaterialInAudit guards against sensitive data entering audit records.
var ErrKeyMaterialInAudit = errors.New("key material must never enter the audit path")

// Archiver persists key material to an encrypted-at-rest file and records a
// sanitized audit event. The failure path never includes key material.
type Archiver struct {
	root  string
	state *store.State
	audit *audit.Sink
}

// NewArchiver creates an archiver.
func NewArchiver(root string, state *store.State, sink *audit.Sink) *Archiver {
	return &Archiver{root: root, state: state, audit: sink}
}

// Archive writes the key material and records a sanitized audit entry.
func (a *Archiver) Archive(certID string, material []byte) error {
	if !ArchiveIntegrity(material) {
		return errors.New("key material integrity check failed")
	}
	path := filepath.Join(a.root, "keys", certID+".key")
	if err := store.WriteFileAtomic(path, material); err != nil {
		// Archive failure takes an independent, sanitized path: only the
		// cert id is audited through the guarded sink. Key material must
		// never enter the audit trail, which has no encryption protection.
		_ = a.audit.Record("key_archive_failed", "cert="+certID)
		return fmt.Errorf("archive key %s: %w", certID, err)
	}
	a.state.PutKey(&store.KeyRecord{CertID: certID, Status: "archived"})
	a.audit.Record("key_archived", "cert="+certID)
	return nil
}

// ArchiveIntegrity validates key material before it is persisted.
func ArchiveIntegrity(material []byte) bool {
	if len(material) < 8 {
		return false
	}
	var sum int
	for _, b := range material {
		sum += int(b)
	}
	return sum%2 == 0
}
