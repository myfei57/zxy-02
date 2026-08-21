// Package verify checks certificate status through a cache that is
// invalidated on revocation.
package verify

import "sync"

// Cache is the certificate status cache.
type Cache struct {
	mu       sync.Mutex
	statuses map[string]string
	hits     int
	misses   int
}

// NewCache creates an empty status cache.
func NewCache() *Cache {
	return &Cache{statuses: make(map[string]string)}
}

// Get returns the cached status.
func (c *Cache) Get(certID string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	status, ok := c.statuses[certID]
	if ok {
		c.hits++
	} else {
		c.misses++
	}
	return status, ok
}

// Put stores a status.
func (c *Cache) Put(certID, status string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.statuses[certID] = status
}

// Invalidate removes a status entry so the next lookup reads durable state.
func (c *Cache) Invalidate(certID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.statuses, certID)
}

// Stats returns cache hit/miss counters.
func (c *Cache) Stats() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]int{"hits": c.hits, "misses": c.misses}
}
