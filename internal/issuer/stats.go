package issuer

// PoolStats describes the serial pool state.
type PoolStats struct {
	Next      int64 `json:"next"`
	Consumed  int   `json:"consumed"`
	Allocated int   `json:"allocated"`
}

// Stats returns a snapshot of the serial pool.
func (p *SerialPool) Stats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return PoolStats{
		Next:      p.next,
		Consumed:  len(p.consumed),
		Allocated: len(p.allocated),
	}
}
