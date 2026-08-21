// Package enrollment handles CSR intake, review and renewal windows.
package enrollment

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"certbridge/internal/store"
)

// ParseCSR derives a deterministic subject, SANs and digest from raw CSR
// bytes. The result is the snapshot that must be bound to issuance.
func ParseCSR(data []byte) store.RequestSnapshot {
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	subject := fmt.Sprintf("cn=dev-%02d", digest[0]%100)
	sans := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		sans = append(sans, fmt.Sprintf("san-%d-%s", i, digest[i:i+2]))
	}
	return store.RequestSnapshot{Subject: subject, SANs: sans, Digest: digest}
}
