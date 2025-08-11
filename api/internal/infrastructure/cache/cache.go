package cache

import (
	"Scribe/internal/domain/entities"
	"sync"
	"time"
)

var (
	SessionCache      Singleton[int64, entities.SessionState]
	PermissionIDCache Singleton[string, int64]
)

// Entry holds the value and its expiration time.
type Entry[V any] struct {
	value  V
	expiry time.Time
}

// Cache is a thread-safe in-memory key-value store with optional TTL support.
type Cache[K comparable, V any] struct {
	mu   sync.Mutex
	data map[K]Entry[V]
}

// Singleton provides a generic way to create singleton instances of Cache[K, V].
type Singleton[K comparable, V any] struct {
	once     sync.Once
	instance *Cache[K, V]
}

// New creates a new Cache instance.
func New[K comparable, V any]() *Cache[K, V] {
	return &Cache[K, V]{
		data: make(map[K]Entry[V]),
	}
}

// Get retrieves the value for the given key if it exists and hasn't expired.
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

// Get returns the singleton instance of Cache[K, V], initializing it if necessary.
func (s *Singleton[K, V]) Get() *Cache[K, V] {
	s.once.Do(func() {
		s.instance = New[K, V]()
	})
	return s.instance
}

// Len returns the number of entries in the cache.
func (c *Cache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.data)
}

// Clear removes all entries from the cache.
func (c *Cache[K, V]) Clear() {
	c.mu.Lock()
	clear(c.data)
	c.mu.Unlock()
}
