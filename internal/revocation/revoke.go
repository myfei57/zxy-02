package revocation

import (
	"time"

	"certbridge/internal/crl"
	"certbridge/internal/store"
	"certbridge/internal/verify"
)

// Service revokes certificates: append the CRL entry, invalidate the
// verification cache and persist the state transition.
type Service struct {
	state *store.State
	crl   *crl.Service
	cache *verify.Cache
}

// NewService wires the revocation service.
func NewService(state *store.State, crl *crl.Service, cache *verify.Cache) *Service {
	return &Service{state: state, crl: crl, cache: cache}
}

// RevokeCertificate revokes a certificate end to end.
func (s *Service) RevokeCertificate(certID, reason string) error {
	cert, ok := s.state.Certificate(certID)
	if !ok {
		return ErrNotActive
	}
	entry, err := Revoke(cert, reason, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return err
	}
	if err := s.crl.Append(entry); err != nil {
		return err
	}
	s.cache.Invalidate(certID)
	return s.state.PutCertificate(cert)
}
