// Package revocation implements the certificate revocation state machine
// and CRL entry generation.
package revocation

// NormalizeReason maps an empty reason to the explicit unspecified value.
func NormalizeReason(reason string) string {
	if reason == "" {
		return "unspecified"
	}
	return reason
}
