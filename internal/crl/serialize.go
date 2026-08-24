package crl

import (
	"fmt"
	"strings"

	"certbridge/internal/store"
)

// EncodeEntries renders the CRL entries as one line per serial.
func EncodeEntries(entries []store.RevocationEntry) string {
	var b strings.Builder
	for _, entry := range entries {
		fmt.Fprintf(&b, "%d\t%s\t%d\n", entry.Serial, entry.Reason, entry.Generation)
	}
	return b.String()
}

// FindEntry returns the entry for a serial.
func FindEntry(entries []store.RevocationEntry, serial int64) (store.RevocationEntry, bool) {
	for _, entry := range entries {
		if entry.Serial == serial {
			return entry, true
		}
	}
	return store.RevocationEntry{}, false
}
