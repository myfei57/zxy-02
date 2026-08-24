// Package console exposes the operations dashboard: JSON APIs, embedded
// pages and status metrics.
package console

import "certbridge/internal/store"

// CountCertificates returns the total number of certificates.
func CountCertificates(state *store.State) int {
	return len(state.ListCertificates())
}

// CountRevocations returns the number of revocation entries.
func CountRevocations(state *store.State) int {
	return len(state.Revocations())
}

// ActiveCount returns how many certificates are in the active state.
func ActiveCount(state *store.State) int {
	count := 0
	for _, cert := range state.ListCertificates() {
		if cert.Status == store.StatusActive {
			count++
		}
	}
	return count
}

// RequestCount returns how many enrollment requests exist.
func RequestCount(state *store.State) int {
	return len(state.ListRequests())
}

// ExpiredCount returns how many certificates are expired.
func ExpiredCount(state *store.State) int {
	return len(state.ExpiredCertificates())
}

// RevokedCount returns how many certificates are revoked.
func RevokedCount(state *store.State) int {
	return len(state.RevokedCertificates())
}
