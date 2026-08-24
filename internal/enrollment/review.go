package enrollment

import (
	"errors"
	"fmt"

	"certbridge/internal/store"
)

// ErrNotPending is returned when an approval targets a non-pending request.
var ErrNotPending = errors.New("request is not pending")

// Approve freezes the snapshot as the reviewed content.
func Approve(state *store.State, requestID string) error {
	req, ok := state.Request(requestID)
	if !ok {
		return fmt.Errorf("unknown request %s", requestID)
	}
	if req.Status != store.StatusPending {
		return ErrNotPending
	}
	if err := RevalidateApproved(req.Snapshot); err != nil {
		return err
	}
	req.Status = store.StatusApproved
	state.PutRequest(req)
	return nil
}

// Reject marks a request as rejected without a snapshot binding.
func Reject(state *store.State, requestID string) error {
	req, ok := state.Request(requestID)
	if !ok {
		return fmt.Errorf("unknown request %s", requestID)
	}
	req.Status = "rejected"
	state.PutRequest(req)
	return nil
}
