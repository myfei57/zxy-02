package verifycase

import (
	"testing"

	"certbridge/internal/issuer"
)

func TestSerialNumberRolledBackOnFailure(t *testing.T) {
	pool := issuer.NewSerialPool(1000)
	serial := pool.Allocate()
	pool.Rollback(serial)
	if pool.Consumed(serial) {
		t.Fatal("rolled-back serial must not be consumed")
	}
}
