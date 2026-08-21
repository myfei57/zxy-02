package revocation

import "certbridge/internal/store"

// Summary counts revocation entries per reason.
func Summary(entries []store.RevocationEntry) map[string]int {
	out := make(map[string]int)
	for _, entry := range entries {
		out[entry.Reason]++
	}
	return out
}

// TotalRevoked returns the count of revoked certificates in state.
func TotalRevoked(state *store.State) int {
	return len(state.Revocations())
}
