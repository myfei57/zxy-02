package issuer

import (
	"fmt"
	"strings"
	"time"

	"certbridge/internal/store"
)

// EncodeCertificate renders a PEM-like representation for delivery.
func EncodeCertificate(cert *store.Certificate) string {
	var b strings.Builder
	fmt.Fprintf(&b, "-----BEGIN CERTIFICATE-----\n")
	fmt.Fprintf(&b, "serial: %d\n", cert.Serial)
	fmt.Fprintf(&b, "subject: %s\n", cert.Subject)
	fmt.Fprintf(&b, "sans: %s\n", strings.Join(cert.SANs, ","))
	fmt.Fprintf(&b, "generation: %d\n", cert.Generation)
	fmt.Fprintf(&b, "status: %s\n", cert.Status)
	fmt.Fprintf(&b, "issued_at: %s\n", cert.IssuedAt)
	fmt.Fprintf(&b, "expires_at: %s\n", cert.ExpiresAt)
	fmt.Fprintf(&b, "-----END CERTIFICATE-----\n")
	return b.String()
}

// IsExpired reports whether a certificate has passed its expiry time.
func IsExpired(cert *store.Certificate, now time.Time) bool {
	expires, err := time.Parse(time.RFC3339, cert.ExpiresAt)
	if err != nil {
		return true
	}
	return now.After(expires)
}

// CertificateFingerprint derives a stable display fingerprint.
func CertificateFingerprint(cert *store.Certificate) string {
	return fmt.Sprintf("CFP-%d-%d", cert.Serial, cert.Generation)
}
