package audit

import "certbridge/internal/store"

// All returns all audit entries.
func (s *Sink) All() []store.AuditEntry {
	return s.state.Audit()
}

// Summary returns per-event counts.
func (s *Sink) Summary() map[string]int {
	counts := make(map[string]int)
	for _, entry := range s.state.Audit() {
		counts[entry.Event]++
	}
	return counts
}
