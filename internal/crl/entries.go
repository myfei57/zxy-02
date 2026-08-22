// Package crl manages the certificate revocation list: durable entries,
// version advancement and distribution.
package crl

import "certbridge/internal/store"

// persistEntries writes revocation entries durably.
func persistEntries(state *store.State, entries ...store.RevocationEntry) error {
	for _, entry := range entries {
		if err := state.AppendRevocation(entry); err != nil {
			return err
		}
	}
	return nil
}
