package verify

import (
	"fmt"
	"time"

	"certbridge/internal/issuer"
	"certbridge/internal/store"
)

// Verifier checks certificates against the status cache and durable state.
type Verifier struct {
	state *store.State
	cache *Cache
}

// NewVerifier creates a verifier.
func NewVerifier(state *store.State, cache *Cache) *Verifier {
	return &Verifier{state: state, cache: cache}
}

// Verify returns whether a certificate is valid for mTLS.
func (v *Verifier) Verify(certID string) (bool, string) {
	if status, ok := v.cache.Get(certID); ok {
		return Allowed(status), status
	}
	cert, ok := v.state.Certificate(certID)
	if !ok {
		return false, "unknown"
	}
	status := cert.Status
	if issuer.IsExpired(cert, time.Now()) {
		status = store.StatusExpired
		v.state.PutCertificate(cert)
	}
	v.cache.Put(certID, status)
	return Allowed(status), status
}

// Status returns the durable status of a certificate.
func (v *Verifier) Status(certID string) (string, error) {
	cert, ok := v.state.Certificate(certID)
	if !ok {
		return "", fmt.Errorf("unknown certificate %s", certID)
	}
	return cert.Status, nil
}

// CacheStats exposes verification cache counters.
func (v *Verifier) CacheStats() map[string]int {
	return v.cache.Stats()
}
