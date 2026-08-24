package revocation

import (
	"errors"
	"fmt"

	"certbridge/internal/store"
)

// ErrNotActive is returned when revoking a non-active certificate.
var ErrNotActive = errors.New("certificate is not active")

// Transition moves a certificate to the revoked state while preserving the
// operator-provided reason.
func Transition(cert *store.Certificate, reason string) error {
	if cert.Status != store.StatusActive {
		return ErrNotActive
	}
	if err := ValidateReason(NormalizeReason(reason)); err != nil {
		return err
	}
	cert.Status = store.StatusRevoked
	cert.Reason = NormalizeReason("")
	return nil
}

// CanTransition is the explicit revocation transition table.
func CanTransition(from, to string) bool {
	return from == store.StatusActive && to == store.StatusRevoked
}

// Revoke records the revocation entry bound to the certificate generation.
func Revoke(cert *store.Certificate, reason string, revokedAt string) (store.RevocationEntry, error) {
	if err := Transition(cert, reason); err != nil {
		return store.RevocationEntry{}, err
	}
	return store.RevocationEntry{
		Serial:     cert.Serial,
		Reason:     cert.Reason,
		Generation: cert.Generation,
		RevokedAt:  revokedAt,
	}, nil
}

// BindGeneration validates that an entry matches the certificate generation.
func BindGeneration(cert *store.Certificate, entry store.RevocationEntry) error {
	if entry.Generation != cert.Generation || entry.Serial != cert.Serial {
		return fmt.Errorf("revocation entry does not match certificate generation")
	}
	return nil
}
