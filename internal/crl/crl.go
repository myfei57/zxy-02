package crl

import (
	"certbridge/internal/store"
)

// Service manages CRL entries and versions.
type Service struct {
	state *store.State
}

// NewService creates the CRL service.
func NewService(state *store.State) *Service {
	return &Service{state: state}
}

// Append stores entries durably and only then advances the version, so a
// crash mid-append can never leave the version ahead of the entries on
// disk. A client reading version N is guaranteed that every entry promised
// by that version is already persisted; the revoked serial can never be
// silently absent from a CRL the client treats as current.
func (s *Service) Append(entries ...store.RevocationEntry) error {
	if err := persistEntries(s.state, entries...); err != nil {
		return err
	}
	return s.AdvanceVersion()
}

// Entries returns all stored revocation entries.
func (s *Service) Entries() []store.RevocationEntry {
	return s.state.Revocations()
}

// Version returns the current CRL version.
func (s *Service) Version() int64 {
	return s.state.Crl().Version
}

// AdvanceVersion bumps the CRL version to the current entry count.
func (s *Service) AdvanceVersion() error {
	crlState := s.state.Crl()
	crlState.Version++
	crlState.EntriesCount = len(s.state.Revocations())
	return s.state.SetCrl(crlState)
}
