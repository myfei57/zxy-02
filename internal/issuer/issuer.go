package issuer

import (
	"errors"
	"fmt"

	"github.com/google/uuid"

	"certbridge/internal/enrollment"
	"certbridge/internal/store"
)

// ErrNotApproved is returned when issuance targets an unapproved request.
var ErrNotApproved = errors.New("request is not approved")

// Issuer issues certificates from approved snapshots with serial accounting.
type Issuer struct {
	state *store.State
	pool  *SerialPool
}

// NewIssuer creates the issuer over a state and serial pool.
func NewIssuer(state *store.State, pool *SerialPool) *Issuer {
	return &Issuer{state: state, pool: pool}
}

// Issue consumes the approval snapshot, allocates a serial and persists the
// certificate before committing the serial.
func (i *Issuer) Issue(requestID string) (*store.Certificate, error) {
	req, ok := i.state.Request(requestID)
	if !ok {
		return nil, fmt.Errorf("unknown request %s", requestID)
	}
	if req.Status != store.StatusApproved {
		return nil, ErrNotApproved
	}
	snapshot := enrollment.ParseCSR(req.Raw)
	serial := i.pool.Allocate()
	cert := BuildCertificate(snapshot, serial, 1)
	cert.ID = uuid.NewString()
	if err := i.state.PutCertificate(cert); err != nil {
		i.pool.Rollback(serial)
		return nil, err
	}
	i.pool.Commit(serial)
	req.Status = store.StatusIssued
	i.state.PutRequest(req)
	return cert, nil
}

// IssueFromSnapshot issues the next generation using the existing snapshot.
func (i *Issuer) IssueFromSnapshot(snapshot store.RequestSnapshot, generation int64) (*store.Certificate, error) {
	serial := i.pool.Allocate()
	cert := BuildCertificate(snapshot, serial, generation)
	cert.ID = uuid.NewString()
	if err := i.state.PutCertificate(cert); err != nil {
		i.pool.Rollback(serial)
		return nil, err
	}
	i.pool.Commit(serial)
	return cert, nil
}
