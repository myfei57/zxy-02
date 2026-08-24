package store

// CertificatesByGeneration returns certificates filtered by generation.
func (s *State) CertificatesByGeneration(generation int64) []*Certificate {
	out := make([]*Certificate, 0)
	for _, cert := range s.ListCertificates() {
		if cert.Generation == generation {
			out = append(out, cert)
		}
	}
	return out
}

// RevocationsByGeneration returns revocation entries filtered by generation.
func (s *State) RevocationsByGeneration(generation int64) []RevocationEntry {
	out := make([]RevocationEntry, 0)
	for _, entry := range s.Revocations() {
		if entry.Generation == generation {
			out = append(out, entry)
		}
	}
	return out
}

// AuditByEvent returns audit entries filtered by event (state-level view).
func (s *State) AuditByEvent(event string) []AuditEntry {
	out := make([]AuditEntry, 0)
	for _, entry := range s.Audit() {
		if entry.Event == event {
			out = append(out, entry)
		}
	}
	return out
}

// KeyRecords returns all key archive records.
func (s *State) KeyRecords() []*KeyRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*KeyRecord, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, k)
	}
	return out
}

// ExpiredCertificates returns certificates in the expired state.
func (s *State) ExpiredCertificates() []*Certificate {
	return s.CertificatesByStatus(StatusExpired)
}

// RevokedCertificates returns certificates in the revoked state.
func (s *State) RevokedCertificates() []*Certificate {
	return s.CertificatesByStatus(StatusRevoked)
}

// AuditCount returns the number of audit entries.
func (s *State) AuditCount() int {
	return len(s.Audit())
}

// KeyCount returns the number of key archive records.
func (s *State) KeyCount() int {
	return len(s.KeyRecords())
}
