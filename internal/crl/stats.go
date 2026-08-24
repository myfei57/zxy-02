package crl

import "certbridge/internal/store"

// Stats aggregates CRL entry counts.
type Stats struct {
	Version      int64         `json:"version"`
	TotalEntries int           `json:"total_entries"`
	ByGeneration map[int64]int `json:"by_generation"`
}

// ComputeStats derives CRL statistics from the stored entries.
func ComputeStats(state *store.State, version int64) Stats {
	entries := state.Revocations()
	byGeneration := make(map[int64]int)
	for _, entry := range entries {
		byGeneration[entry.Generation]++
	}
	return Stats{Version: version, TotalEntries: len(entries), ByGeneration: byGeneration}
}
