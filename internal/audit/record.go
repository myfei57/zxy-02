// Package audit records sanitized operational events.
package audit

import (
	"strings"

	"github.com/google/uuid"

	"certbridge/internal/store"
)

// Sink writes audit entries to the state.
type Sink struct {
	state *store.State
}

// NewSink creates an audit sink.
func NewSink(state *store.State) *Sink {
	return &Sink{state: state}
}

// Record appends one audit entry. Sensitive key material markers are
// refused as a hard backstop.
func (s *Sink) Record(event, detail string) error {
	if strings.Contains(detail, "KEY:") {
		return ErrKeyMaterialInAudit
	}
	s.state.AppendAudit(store.AuditEntry{
		ID:     uuid.NewString(),
		Event:  event,
		Detail: detail,
		At:     store.NowUTC(),
	})
	return nil
}
