package cache

import (
	"sync"
	"time"
)

type entry struct {
	scannedAt time.Time
}

// ImageCache tracks recently scanned images by digest to avoid redundant scans.
type ImageCache struct {
	mu      sync.RWMutex
	entries map[string]entry
	ttl     time.Duration
}

// New creates an ImageCache with the given TTL.
func New(ttl time.Duration) *ImageCache {
	return &ImageCache{
		entries: make(map[string]entry),
		ttl:     ttl,
	}
}

// ShouldScan returns true if the image digest has not been scanned recently.
func (c *ImageCache) ShouldScan(digest string) bool {
	if digest == "" {
		return true
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[digest]
	if !ok {
		return true
	}
	return time.Since(e.scannedAt) > c.ttl
}

// MarkScanned records that an image digest was just scanned.
func (c *ImageCache) MarkScanned(digest string) {
	if digest == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[digest] = entry{scannedAt: time.Now()}
}

// Cleanup removes expired entries from the cache.
func (c *ImageCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, e := range c.entries {
		if now.Sub(e.scannedAt) > c.ttl {
			delete(c.entries, k)
		}
	}
}

// Size returns the number of entries in the cache.
func (c *ImageCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
