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

// Append stores entries durably. Version advancement happens at publish
// time, never before the entries are on disk.
func (s *Service) Append(entries ...store.RevocationEntry) error {
	if err := s.AdvanceVersion(); err != nil {
		return err
	}
	return persistEntries(s.state, entries...)
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
