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

// Allocate reserves a candidate serial without consuming it. The number is
// held in the allocated set until Commit or Rollback resolves it.
func (p *SerialPool) Allocate() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.next++
	for p.consumed[p.next] || p.allocated[p.next] {
		// Skip anything already taken so a rehydrated or in-flight serial is
		// never handed out twice.
		p.next++
	}
	p.allocated[p.next] = true
	return p.next
}

// Commit marks a serial as durably consumed.
func (p *SerialPool) Commit(serial int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.allocated, serial)
	p.consumed[serial] = true
}

// Rollback returns a serial to the pool after a failed issuance.
func (p *SerialPool) Rollback(serial int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.allocated, serial)
	delete(p.consumed, serial)
}

// Consumed reports whether a serial was committed.
func (p *SerialPool) Consumed(serial int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.consumed[serial]
}

// Rehydrate rebuilds the consumed set from already-persisted certificates and
// advances next past every serial still on disk. This must be called after
// state load on startup so a restart never reissues a serial that was already
// handed out.
func (p *SerialPool) Rehydrate(serials []int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range serials {
		p.consumed[s] = true
		delete(p.allocated, s)
		if s >= p.next {
			p.next = s
		}
	}
}
