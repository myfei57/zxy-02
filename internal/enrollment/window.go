package enrollment

import (
	"time"

	"certbridge/internal/store"
)

// WindowManager tracks renewal eligibility windows.
type WindowManager struct {
	state *store.State
}

// NewWindowManager creates the renewal window manager.
func NewWindowManager(state *store.State) *WindowManager {
	return &WindowManager{state: state}
}

// Open starts a renewal window for a certificate.
func (m *WindowManager) Open(certID string, windowSeconds int64) {
	now := time.Now().Unix()
	m.state.PutWindow(&store.RenewalWindow{
		CertID:   certID,
		OpensAt:  now,
		ClosesAt: now + windowSeconds,
		Elapsed:  0,
	})
}

// Elapsed returns the business elapsed seconds of a window.
func (m *WindowManager) Elapsed(certID string) int64 {
	window, ok := m.state.Window(certID)
	if !ok {
		return 0
	}
	now := time.Now().Unix()
	if now > window.ClosesAt {
		return window.ClosesAt - window.OpensAt
	}
	return now - window.OpensAt
}

// Remaining returns the seconds left in a renewal window.
func (m *WindowManager) Remaining(certID string) int64 {
	window, ok := m.state.Window(certID)
	if !ok {
		return 0
	}
	now := time.Now().Unix()
	if now >= window.ClosesAt {
		return 0
	}
	return window.ClosesAt - now
}

// IsOpen reports whether a renewal window is currently open.
func (m *WindowManager) IsOpen(certID string) bool {
	return m.Remaining(certID) > 0
}

// Close marks a renewal window finished.
func (m *WindowManager) Close(certID string) {
	window, ok := m.state.Window(certID)
	if !ok {
		return
	}
	now := time.Now().Unix()
	window.ClosesAt = now
	window.OpensAt = now
	m.state.PutWindow(window)
}

// Recover rebuilds a window after restart. Downtime is not counted as
// business elapsed time; the persisted elapsed value is preserved.
func (m *WindowManager) Recover(certID string, downtime int64) {
	window, ok := m.state.Window(certID)
	if !ok {
		return
	}
	window.Elapsed += downtime
	window.OpensAt = time.Now().Unix() - window.Elapsed
	m.state.PutWindow(window)
}

// RenewCertificate issues the next generation and keeps the new certificate
// active without touching revocation records.
func (m *WindowManager) RenewCertificate(certID string, issue func(generation int64) (*store.Certificate, error)) (*store.Certificate, error) {
	cert, ok := m.state.Certificate(certID)
	if !ok {
		return nil, ErrNotPending
	}
	next, err := issue(cert.Generation + 1)
	if err != nil {
		return nil, err
	}
	return next, nil
}
