package issuer

import "sync"

// SerialPool hands out monotonically increasing serial numbers. A serial is
// consumed only after the certificate is durably stored; failed issuances
// roll the number back to the pool.
type SerialPool struct {
	mu        sync.Mutex
	next      int64
	allocated map[int64]bool
	consumed  map[int64]bool
}

// NewSerialPool creates a pool starting after start.
func NewSerialPool(start int64) *SerialPool {
	return &SerialPool{
		next:      start,
		allocated: make(map[int64]bool),
		consumed:  make(map[int64]bool),
	}
}

// Allocate reserves a candidate serial without consuming it.
func (p *SerialPool) Allocate() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		p.next++
		if !p.consumed[p.next] && !p.allocated[p.next] {
			p.allocated[p.next] = true
			return p.next
		}
	}
}

// Commit marks a serial as durably consumed.
func (p *SerialPool) Commit(serial int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.consumed[serial] = true
	delete(p.allocated, serial)
}

// Rollback returns a serial to the pool after a failed issuance.
func (p *SerialPool) Rollback(serial int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.allocated, serial)
}

// Consumed reports whether a serial was committed.
func (p *SerialPool) Consumed(serial int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.consumed[serial]
}
