package cache

import (
	"sync"
	"testing"
	"time"
)

// TestNew tests the creation of a new Cache instance.
func TestNew(t *testing.T) {
	cache := New[string, int]()
	if cache == nil {
		t.Fatal("New() returned nil")
	}
	if cache.data == nil {
		t.Fatal("New() did not initialize data map")
	}
	if len(cache.data) != 0 {
		t.Errorf("New() data map is not empty, got %d entries", len(cache.data))
	}
}

// TestSetAndGet tests setting and getting values without TTL.
func TestSetAndGet(t *testing.T) {
	cache := New[string, string]()
	cache.Set("key1", "value1", 0)
	value, ok := cache.Get("key1")
	if !ok {
		t.Error("Get(key1) returned ok=false")
	}
	if value != "value1" {
		t.Errorf("Get(key1) = %v, want value1", value)
	}
}

// TestGetNonExistent tests getting a non-existent key.
func TestGetNonExistent(t *testing.T) {
	cache := New[string, string]()
	value, ok := cache.Get("nonexistent")
	if ok {
		t.Error("Get(nonexistent) returned ok=true")
	}
	if value != "" {
		t.Errorf("Get(nonexistent) = %v, want empty string", value)
	}
}

// TestSetWithTTL tests setting a value with a TTL and checking expiration.
func TestSetWithTTL(t *testing.T) {
	cache := New[string, string]()
	cache.Set("key1", "value1", 100*time.Millisecond)
	value, ok := cache.Get("key1")
	if !ok {
		t.Error("Get(key1) returned ok=false before expiration")
	}
	if value != "value1" {
		t.Errorf("Get(key1) = %v, want value1", value)
	}
	time.Sleep(150 * time.Millisecond)
	value, ok = cache.Get("key1")
	if ok {
		t.Error("Get(key1) returned ok=true after expiration")
	}
	if value != "" {
		t.Errorf("Get(key1) = %v, want empty string after expiration", value)
	}
}

// TestDelete tests deleting a key from the cache.
func TestDelete(t *testing.T) {
	cache := New[string, string]()
	cache.Set("key1", "value1", 0)
	cache.Delete("key1")
	value, ok := cache.Get("key1")
	if ok {
		t.Error("Get(key1) returned ok=true after deletion")
	}
	if value != "" {
		t.Errorf("Get(key1) = %v, want empty string after deletion", value)
	}
}

// TestConcurrentAccess tests thread safety with concurrent read/write operations.
func TestConcurrentAccess(t *testing.T) {
	cache := New[int, string]()
	var wg sync.WaitGroup
	numGoroutines := 100
	keys := make([]int, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		keys[i] = i
	}
	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			cache.Set(k, "value"+string(rune(k)), 0)
		}(i)
	}
	wg.Wait()
	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			value, ok := cache.Get(k)
			if !ok {
				t.Errorf("Get(%d) returned ok=false", k)
			}
			expected := "value" + string(rune(k))
			if value != expected {
				t.Errorf("Get(%d) = %v, want %s", k, value, expected)
			}
		}(i)
	}
	wg.Wait()
	// Concurrent read/write mix
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		if i%2 == 0 {
			go func(k int) {
				defer wg.Done()
				cache.Set(k, "newvalue"+string(rune(k)), 0)
			}(i)
		} else {
			go func(k int) {
				defer wg.Done()
				cache.Get(k)
			}(i)
		}
	}
	wg.Wait()
}

// TestCustomType tests using a custom struct as the value type, simulating a user identified by ID with metadata.
func TestCustomType(t *testing.T) {
	type UserMetadata struct {
		Name     string
		Email    string
		Metadata map[string]string
	}

	cache := New[int, UserMetadata]()

	user := UserMetadata{
		Name:  "Alice",
		Email: "alice@example.com",
		Metadata: map[string]string{
			"role":  "admin",
			"level": "5",
		},
	}

	cache.Set(123, user, 0)

	retrieved, ok := cache.Get(123)
	if !ok {
		t.Error("Get(123) returned ok=false")
	}
	if retrieved.Name != "Alice" {
		t.Errorf("Retrieved Name = %v, want Alice", retrieved.Name)
	}
	if retrieved.Email != "alice@example.com" {
		t.Errorf("Retrieved Email = %v, want alice@example.com", retrieved.Email)
	}
	if retrieved.Metadata["role"] != "admin" {
		t.Errorf("Retrieved Metadata[role] = %v, want admin", retrieved.Metadata["role"])
	}
	if retrieved.Metadata["level"] != "5" {
		t.Errorf("Retrieved Metadata[level] = %v, want 5", retrieved.Metadata["level"])
	}
}

// TestLen tests the Len method for counting entries in the cache.
func TestLen(t *testing.T) {
	cache := New[string, int]()
	if cache.Len() != 0 {
		t.Errorf("Len() on empty cache = %d, want 0", cache.Len())
	}

	cache.Set("a", 1, 0)
	cache.Set("b", 2, 0)
	if cache.Len() != 2 {
		t.Errorf("Len() after two sets = %d, want 2", cache.Len())
	}

	// Test with expired entry (not purged yet)
	cache.Set("c", 3, 1*time.Millisecond)
	time.Sleep(2 * time.Millisecond)
	if cache.Len() != 3 {
		t.Errorf("Len() with expired entry = %d, want 3", cache.Len())
	}

	// Purge by getting
	_, _ = cache.Get("c")
	if cache.Len() != 2 {
		t.Errorf("Len() after purging expired = %d, want 2", cache.Len())
	}
}

// TestClear tests the Clear method for removing all entries from the cache.
func TestClear(t *testing.T) {
	cache := New[string, int]()
	cache.Set("a", 1, 0)
	cache.Set("b", 2, 0)
	if cache.Len() != 2 {
		t.Errorf("Len() before clear = %d, want 2", cache.Len())
	}

	cache.Clear()

	if cache.Len() != 0 {
		t.Errorf("Len() after clear = %d, want 0", cache.Len())
	}

	_, ok := cache.Get("a")
	if ok {
		t.Error("Get(a) after clear returned ok=true")
	}

	_, ok = cache.Get("b")
	if ok {
		t.Error("Get(b) after clear returned ok=true")
	}
}
