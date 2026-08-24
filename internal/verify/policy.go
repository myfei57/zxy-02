package verify

import "certbridge/internal/store"

// Allowed reports whether a certificate status may pass mTLS verification.
func Allowed(status string) bool {
	return status == store.StatusActive
}
