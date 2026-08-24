// Package store owns the durable and in-memory state of the CertBridge
// PKI/CA service: requests, certificates, revocation entries, CRL state,
// key records, renewal windows and audit entries.
package store

// Certificate lifecycle states.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusIssued   = "issued"
	StatusActive   = "active"
	StatusRevoked  = "revoked"
	StatusExpired  = "expired"
)

// Certificate is one issued mTLS certificate.
type Certificate struct {
	ID         string   `json:"id"`
	Serial     int64    `json:"serial"`
	Subject    string   `json:"subject"`
	SANs       []string `json:"sans"`
	Generation int64    `json:"generation"`
	Status     string   `json:"status"`
	Reason     string   `json:"reason,omitempty"`
	IssuedAt   string   `json:"issued_at"`
	ExpiresAt  string   `json:"expires_at"`
}

// Request is one CSR enrollment and its immutable approval snapshot.
type Request struct {
	ID          string          `json:"id"`
	Fingerprint string          `json:"fingerprint"`
	Status      string          `json:"status"`
	Raw         []byte          `json:"raw,omitempty"`
	Snapshot    RequestSnapshot `json:"snapshot"`
}

// RequestSnapshot is the frozen content the reviewer approved.
type RequestSnapshot struct {
	Subject string   `json:"subject"`
	SANs    []string `json:"sans"`
	Digest  string   `json:"digest"`
}

// RevocationEntry is one revoked serial on the CRL.
type RevocationEntry struct {
	Serial     int64  `json:"serial"`
	Reason     string `json:"reason"`
	Generation int64  `json:"generation"`
	RevokedAt  string `json:"revoked_at"`
}

// CrlState tracks the published CRL generation.
type CrlState struct {
	Version      int64 `json:"version"`
	EntriesCount int   `json:"entries_count"`
}

// KeyRecord tracks the private key archive lifecycle.
type KeyRecord struct {
	CertID string `json:"cert_id"`
	Status string `json:"status"`
}

// RenewalWindow is one certificate's renewal eligibility window.
type RenewalWindow struct {
	CertID   string `json:"cert_id"`
	OpensAt  int64  `json:"opens_at"`
	ClosesAt int64  `json:"closes_at"`
	Elapsed  int64  `json:"elapsed"`
}

// AuditEntry is one sanitized audit record.
type AuditEntry struct {
	ID     string `json:"id"`
	Event  string `json:"event"`
	Detail string `json:"detail"`
	At     string `json:"at"`
}
