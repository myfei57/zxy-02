package enrollment

import (
	"github.com/google/uuid"

	"certbridge/internal/store"
)

// Submit records a new CSR request with its immutable approval snapshot.
func Submit(state *store.State, data []byte) (string, error) {
	snapshot := ParseCSR(data)
	if err := ValidateSnapshot(snapshot); err != nil {
		return "", err
	}
	snapshot.Subject = SanitizeSubject(snapshot.Subject)
	req := &store.Request{
		ID:          uuid.NewString(),
		Fingerprint: snapshot.Digest[:16],
		Status:      store.StatusPending,
		Raw:         data,
		Snapshot:    snapshot,
	}
	state.PutRequest(req)
	return req.ID, nil
}
