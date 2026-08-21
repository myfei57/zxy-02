package enrollment

import (
	"errors"
	"strings"

	"certbridge/internal/store"
)

// ErrInvalidSubject is returned when a CSR subject fails validation.
var ErrInvalidSubject = errors.New("subject must start with cn=")

// ValidateSnapshot checks the parsed snapshot before it is frozen.
func ValidateSnapshot(snapshot store.RequestSnapshot) error {
	if !strings.HasPrefix(snapshot.Subject, "cn=") {
		return ErrInvalidSubject
	}
	if len(snapshot.SANs) == 0 {
		return errors.New("at least one SAN is required")
	}
	if len(snapshot.Digest) < 8 {
		return errors.New("snapshot digest is missing")
	}
	return nil
}

// RevalidateApproved re-checks the frozen snapshot at approval time so the
// reviewed content always satisfies the current policy.
func RevalidateApproved(snapshot store.RequestSnapshot) error {
	return ValidateSnapshot(snapshot)
}

// SanitizeSubject strips characters that are unsafe in certificate output.
func SanitizeSubject(subject string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, subject)
}
