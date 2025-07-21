package cache

import (
	"sync"
	"time"
)

// Entry sets the type for generic entries into the cache and an expiry time
type Entry[V any] struct {
	value  V
	expiry time.Time
}

// Cache generic and thread safe in-memory key-value store
type Cache[K comparable, V any] struct {
	mu   sync.Mutex
	data map[K]Entry[V]
}

// New creates a new instance of Cache
func New[K comparable, V any]() *Cache[K, V] {
	return &Cache[K, V]{
		data: make(map[K]Entry[V]),
	}
}

// Get retrieves value for key if Entry has not expired
func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	entry, ok := c.data[key]
	if !ok {
		c.mu.Unlock()
		var zero V
		return zero, false
	}
	if !entry.expiry.IsZero() && time.Now().After(entry.expiry) {
		delete(c.data, key)
		c.mu.Unlock()
		var zero V
		return zero, false
	}
	value := entry.value
	c.mu.Unlock()
	return value, true
}

// Set stores the value for the given key with an optional TTL.
// If ttl <= 0, the entry does not expire.
func (c *Cache[K, V]) Set(key K, value V, ttl time.Duration) {
	expiry := time.Time{}
	if ttl > 0 {
		expiry = time.Now().Add(ttl)
	}
	c.mu.Lock()
	c.data[key] = Entry[V]{value: value, expiry: expiry}
	c.mu.Unlock()
}

// Delete removes the entry for the given key.
func (c *Cache[K, V]) Delete(key K) {
	c.mu.Lock()
	delete(c.data, key)
	c.mu.Unlock()
}
