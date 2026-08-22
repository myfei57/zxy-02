package enrollment

import "certbridge/internal/store"

// QueueSummary counts requests by status.
func QueueSummary(state *store.State) map[string]int {
	out := make(map[string]int)
	for _, req := range state.ListRequests() {
		out[req.Status]++
	}
	return out
}

// PendingRequests returns requests still awaiting review.
func PendingRequests(state *store.State) []*store.Request {
	return state.RequestsByStatus(store.StatusPending)
}
