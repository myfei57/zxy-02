package audit

// Trim keeps only the newest max entries in the audit trail.
func (s *Sink) Trim(max int) int {
	all := s.state.Audit()
	if len(all) <= max {
		return 0
	}
	removed := len(all) - max
	s.state.ReplaceAudit(all[len(all)-max:])
	return removed
}
