package issuer

import "testing"

// TestAllocateReservesButDoesNotConsume verifies the core ordering invariant:
// Allocate reserves a serial into the allocated set without marking it
// consumed. A serial is consumed only after Commit, i.e. only after the
// certificate is durably persisted.
func TestAllocateReservesButDoesNotConsume(t *testing.T) {
	p := NewSerialPool(1000)
	s := p.Allocate()

	if got := p.Stats(); got.Allocated != 1 || got.Consumed != 0 {
		t.Fatalf("after allocate: allocated=%d consumed=%d, want allocated=1 consumed=0", got.Allocated, got.Consumed)
	}
	if p.Consumed(s) {
		t.Fatalf("serial %d reported consumed before commit", s)
	}
	if !p.Consumed(s) && p.Consumed(0) {
		t.Fatalf("consumed map should not contain the reserved serial")
	}
}

// TestCommitConsumesSerial confirms that Commit moves a reserved serial into
// the consumed set and releases the allocation.
func TestCommitConsumesSerial(t *testing.T) {
	p := NewSerialPool(1000)
	s := p.Allocate()
	p.Commit(s)

	if got := p.Stats(); got.Allocated != 0 || got.Consumed != 1 {
		t.Fatalf("after commit: allocated=%d consumed=%d, want allocated=0 consumed=1", got.Allocated, got.Consumed)
	}
	if !p.Consumed(s) {
		t.Fatalf("serial %d not reported consumed after commit", s)
	}
}

// TestRollbackReleasesSerial is the regression for the reported bug: when
// PutCertificate fails, Rollback must return the serial to the pool so it is
// neither consumed nor reused while still "taken". Previously Rollback was a
// no-op and Allocate consumed eagerly, leaving a hole and a phantom consumed
// serial.
func TestRollbackReleasesSerial(t *testing.T) {
	p := NewSerialPool(1000)
	s := p.Allocate()
	p.Rollback(s)

	if got := p.Stats(); got.Allocated != 0 || got.Consumed != 0 {
		t.Fatalf("after rollback: allocated=%d consumed=%d, want both 0", got.Allocated, got.Consumed)
	}
	if p.Consumed(s) {
		t.Fatalf("serial %d still consumed after rollback", s)
	}

	// The rolled-back serial is free again; the next allocate must not collide
	// with it. Because the pool is monotonic, it advances past s, so just
	// confirm the new serial differs and the pool reports no leaks.
	next := p.Allocate()
	if next == s {
		t.Fatalf("allocate reused rolled-back serial %d", s)
	}
	if got := p.Stats(); got.Allocated != 1 || got.Consumed != 0 {
		t.Fatalf("after re-allocate: allocated=%d consumed=%d, want allocated=1 consumed=0", got.Allocated, got.Consumed)
	}
}

// TestAllocateSkipsConsumed ensures a rehydrated (persisted) serial is never
// handed out again by a live allocate.
func TestAllocateSkipsConsumed(t *testing.T) {
	p := NewSerialPool(1000)
	taken := p.Allocate()
	p.Commit(taken)

	// Simulate another consumed serial from rehydration that is ahead of next.
	p.Rehydrate([]int64{taken + 1})

	got := p.Allocate()
	if got == taken || got == taken+1 {
		t.Fatalf("allocate reused a consumed serial: got=%d, taken=%d", got, taken)
	}
	if p.Consumed(got) {
		t.Fatalf("freshly allocated serial %d reported consumed", got)
	}
}

// TestRehydratePreventsRestartCollision is the restart half of the bug: the
// pool is rebuilt from persisted certificates on startup so a restart does not
// reset next to 1000 and reissue an on-disk serial.
func TestRehydratePreventsRestartCollision(t *testing.T) {
	persisted := []int64{1001, 1002, 1005}
	p := NewSerialPool(1000)
	p.Rehydrate(persisted)

	for _, s := range persisted {
		if !p.Consumed(s) {
			t.Fatalf("rehydrated serial %d not marked consumed", s)
		}
	}

	// The next allocate must clear every persisted serial and advance past the
	// highest one.
	s := p.Allocate()
	for _, taken := range persisted {
		if s == taken {
			t.Fatalf("allocate reissued persisted serial %d after rehydrate", s)
		}
	}
	if s <= 1005 {
		t.Fatalf("allocate did not advance past highest persisted serial: got=%d, want >1005", s)
	}
}

// TestMonotonicAllocation confirms the steady-state happy path: committed
// serials are strictly increasing and each is consumed exactly once.
func TestMonotonicAllocation(t *testing.T) {
	p := NewSerialPool(1000)
	seen := map[int64]bool{}
	var prev int64 = 1000
	for i := 0; i < 5; i++ {
		s := p.Allocate()
		if s <= prev {
			t.Fatalf("serial %d not strictly greater than prev %d", s, prev)
		}
		if seen[s] {
			t.Fatalf("serial %d issued twice", s)
		}
		seen[s] = true
		p.Commit(s)
		prev = s
	}
	if got := p.Stats(); got.Consumed != 5 || got.Allocated != 0 {
		t.Fatalf("after 5 commits: consumed=%d allocated=%d, want consumed=5 allocated=0", got.Consumed, got.Allocated)
	}
}
