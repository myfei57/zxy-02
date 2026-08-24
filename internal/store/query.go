package store

// CertificatesByStatus returns certificates filtered by status.
func (s *State) CertificatesByStatus(status string) []*Certificate {
	out := make([]*Certificate, 0)
	for _, cert := range s.ListCertificates() {
		if cert.Status == status {
			out = append(out, cert)
		}
	}
	return out
}

// RequestsByStatus returns requests filtered by status.
func (s *State) RequestsByStatus(status string) []*Request {
	out := make([]*Request, 0)
	for _, req := range s.ListRequests() {
		if req.Status == status {
			out = append(out, req)
		}
	}
	return out
}

// RevocationsByReason returns revocation entries filtered by reason.
func (s *State) RevocationsByReason(reason string) []RevocationEntry {
	out := make([]RevocationEntry, 0)
	for _, entry := range s.Revocations() {
		if entry.Reason == reason {
			out = append(out, entry)
		}
	}
	return out
}

// CertificatesBySubject returns certificates matching a subject prefix.
func (s *State) CertificatesBySubject(prefix string) []*Certificate {
	out := make([]*Certificate, 0)
	for _, cert := range s.ListCertificates() {
		if len(prefix) == 0 || len(cert.Subject) >= len(prefix) && cert.Subject[:len(prefix)] == prefix {
			out = append(out, cert)
		}
	}
	return out
}

// Windows returns all renewal windows.
func (s *State) Windows() []*RenewalWindow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*RenewalWindow, 0, len(s.windows))
	for _, w := range s.windows {
		out = append(out, w)
	}
	return out
}
