// Package issuer builds certificates from approved snapshots, allocates
// serials and drives issuance state transitions.
package issuer

import (
	"time"

	"certbridge/internal/store"
)

// BuildCertificate constructs a certificate exclusively from the approval
// snapshot; raw request content is never consulted.
func BuildCertificate(snapshot store.RequestSnapshot, serial int64, generation int64) *store.Certificate {
	now := time.Now().UTC().Format(time.RFC3339)
	return &store.Certificate{
		Serial:     serial,
		Subject:    snapshot.Subject,
		SANs:       append([]string(nil), snapshot.SANs...),
		Generation: generation,
		Status:     store.StatusActive,
		IssuedAt:   now,
		ExpiresAt:  time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339),
	}
}
