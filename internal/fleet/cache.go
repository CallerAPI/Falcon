package fleet

import (
	"sync"
	"time"

	"github.com/callerapi/falcon/internal/store"
)

// Cache is the last behaviour snapshot from the fleet hub. Screen reads it
// from memory. A stale snapshot is ignored so a dead hub cannot freeze
// yesterday's numbers into today's score.
type Cache struct {
	mu     sync.RWMutex
	at     time.Time
	maxAge time.Duration
	rows   map[string]store.Activity
}

func NewCache(maxAge time.Duration) *Cache {
	if maxAge <= 0 {
		maxAge = time.Minute
	}
	return &Cache{maxAge: maxAge, rows: map[string]store.Activity{}}
}

// Replace stores a fresh snapshot.
func (c *Cache) Replace(rows map[string]store.Activity) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = time.Now()
	if rows == nil {
		rows = map[string]store.Activity{}
	}
	c.rows = rows
}

// Merge adds another node's counts onto the local activity. Distinct
// callees are summed, which can only over-count, and that reason only
// flags. A stale cache returns local unchanged.
func (c *Cache) Merge(from string, local store.Activity) store.Activity {
	if c == nil || from == "" {
		return local
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.at.IsZero() || time.Since(c.at) > c.maxAge {
		return local
	}
	remote, ok := c.rows[from]
	if !ok {
		return local
	}
	local.Calls += remote.Calls
	local.DistinctCallees += remote.DistinctCallees
	local.Completed += remote.Completed
	local.Answered += remote.Answered
	local.TalkSeconds += remote.TalkSeconds
	local.HoneypotHits += remote.HoneypotHits
	return local
}
