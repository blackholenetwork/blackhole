package cache

import (
	"sync"
	"testing"
	"time"
)

func TestNewCache(t *testing.T) {
	t.Run("basic cache creation", func(t *testing.T) {
		c := New[string, int]()
		if c == nil {
			t.Fatal("New() returned nil")
		}
		if c.Size() != 0 {
			t.Errorf("New cache should be empty, got size %d", c.Size())
		}
		c.Close()
	})

	t.Run("cache with TTL", func(t *testing.T) {
		c := New[string, int](WithTTL[string, int](time.Second))
		defer c.Close()
		
		if c.ttl != time.Second {
			t.Errorf("Expected TTL of 1s, got %v", c.ttl)
		}
	})

	t.Run("cache with max size", func(t *testing.T) {
		c := New[string, int](WithMaxSize[string, int](100))
		defer c.Close()
		
		if c.maxSize != 100 {
			t.Errorf("Expected max size of 100, got %d", c.maxSize)
		}
	})

	t.Run("cache with evict callback", func(t *testing.T) {
		evicted := false
		c := New[string, int](WithEvictCallback[string, int](func(k string, v int) {
			evicted = true
		}))
		defer c.Close()
		
		c.Set("key", 1)
		c.Delete("key")
		
		if !evicted {
			t.Error("Evict callback was not called")
		}
	})
}

func TestCacheSetGet(t *testing.T) {
	c := New[string, string]()
	defer c.Close()

	t.Run("basic set and get", func(t *testing.T) {
		c.Set("key1", "value1")
		
		val, ok := c.Get("key1")
		if !ok {
			t.Error("Get() should return true for existing key")
		}
		if val != "value1" {
			t.Errorf("Get() = %v, want %v", val, "value1")
		}
	})

	t.Run("overwrite existing key", func(t *testing.T) {
		c.Set("key1", "value1")
		c.Set("key1", "value2")
		
		val, ok := c.Get("key1")
		if !ok {
			t.Error("Get() should return true for existing key")
		}
		if val != "value2" {
			t.Errorf("Get() = %v, want %v", val, "value2")
		}
	})

	t.Run("get non-existent key", func(t *testing.T) {
		val, ok := c.Get("nonexistent")
		if ok {
			t.Error("Get() should return false for non-existent key")
		}
		if val != "" {
			t.Errorf("Get() should return zero value for non-existent key, got %v", val)
		}
	})

	t.Run("different types", func(t *testing.T) {
		intCache := New[int, int]()
		defer intCache.Close()
		
		intCache.Set(1, 100)
		intCache.Set(2, 200)
		
		val1, _ := intCache.Get(1)
		val2, _ := intCache.Get(2)
		
		if val1 != 100 || val2 != 200 {
			t.Errorf("Expected values 100 and 200, got %d and %d", val1, val2)
		}
	})
}

func TestCacheDelete(t *testing.T) {
	c := New[string, int]()
	defer c.Close()

	c.Set("key1", 1)
	c.Set("key2", 2)

	t.Run("delete existing key", func(t *testing.T) {
		c.Delete("key1")
		
		_, ok := c.Get("key1")
		if ok {
			t.Error("Key should not exist after deletion")
		}
		
		// key2 should still exist
		val, ok := c.Get("key2")
		if !ok || val != 2 {
			t.Error("Other keys should not be affected by deletion")
		}
	})

	t.Run("delete non-existent key", func(t *testing.T) {
		// Should not panic
		c.Delete("nonexistent")
	})

	t.Run("delete with callback", func(t *testing.T) {
		var evictedKey string
		var evictedValue int
		
		c2 := New[string, int](WithEvictCallback[string, int](func(k string, v int) {
			evictedKey = k
			evictedValue = v
		}))
		defer c2.Close()
		
		c2.Set("test", 42)
		c2.Delete("test")
		
		if evictedKey != "test" || evictedValue != 42 {
			t.Errorf("Evict callback received wrong values: key=%v, value=%v", evictedKey, evictedValue)
		}
	})
}

func TestCacheClear(t *testing.T) {
	evictCount := 0
	c := New[string, int](WithEvictCallback[string, int](func(k string, v int) {
		evictCount++
	}))
	defer c.Close()

	// Add multiple items
	for i := 0; i < 10; i++ {
		c.Set(string(rune('a'+i)), i)
	}

	if c.Size() != 10 {
		t.Errorf("Expected size 10, got %d", c.Size())
	}

	c.Clear()

	if c.Size() != 0 {
		t.Errorf("Cache should be empty after Clear(), got size %d", c.Size())
	}

	if evictCount != 10 {
		t.Errorf("Expected 10 evictions, got %d", evictCount)
	}

	// Should be able to add items after clear
	c.Set("new", 100)
	val, ok := c.Get("new")
	if !ok || val != 100 {
		t.Error("Should be able to use cache after Clear()")
	}
}

func TestCacheTTL(t *testing.T) {
	c := New[string, string](WithTTL[string, string](50 * time.Millisecond))
	defer c.Close()

	t.Run("item expires", func(t *testing.T) {
		c.Set("key1", "value1")
		
		// Should exist immediately
		val, ok := c.Get("key1")
		if !ok || val != "value1" {
			t.Error("Item should exist immediately after setting")
		}
		
		// Wait for expiration
		time.Sleep(60 * time.Millisecond)
		
		// Should be expired
		_, ok = c.Get("key1")
		if ok {
			t.Error("Item should have expired")
		}
	})

	t.Run("cleanup removes expired items", func(t *testing.T) {
		c.Set("key2", "value2")
		c.Set("key3", "value3")
		
		// Wait for expiration
		time.Sleep(60 * time.Millisecond)
		
		// Trigger cleanup
		c.cleanup()
		
		if c.Size() != 0 {
			t.Errorf("Cleanup should remove expired items, got size %d", c.Size())
		}
	})

	t.Run("TTL refresh on set", func(t *testing.T) {
		c.Set("key4", "value4")
		
		// Wait half the TTL
		time.Sleep(25 * time.Millisecond)
		
		// Update the value (should refresh TTL)
		c.Set("key4", "value4-updated")
		
		// Wait another half TTL (original would have expired)
		time.Sleep(30 * time.Millisecond)
		
		// Should still exist
		val, ok := c.Get("key4")
		if !ok || val != "value4-updated" {
			t.Error("Item TTL should be refreshed on update")
		}
	})
}

func TestCacheMaxSize(t *testing.T) {
	evictedKeys := make([]string, 0)
	c := New[string, int](
		WithMaxSize[string, int](3),
		WithEvictCallback[string, int](func(k string, v int) {
			evictedKeys = append(evictedKeys, k)
		}),
	)
	defer c.Close()

	// Add items up to max size
	c.Set("a", 1)
	c.Set("b", 2)
	c.Set("c", 3)

	if c.Size() != 3 {
		t.Errorf("Expected size 3, got %d", c.Size())
	}

	// Add one more item
	c.Set("d", 4)

	// Should still be at max size
	if c.Size() != 3 {
		t.Errorf("Size should not exceed max, got %d", c.Size())
	}

	// One item should have been evicted
	if len(evictedKeys) != 1 {
		t.Errorf("Expected 1 eviction, got %d", len(evictedKeys))
	}

	// New item should exist
	val, ok := c.Get("d")
	if !ok || val != 4 {
		t.Error("New item should exist in cache")
	}
}

func TestCacheConcurrency(t *testing.T) {
	c := New[int, int]()
	defer c.Close()

	const goroutines = 10
	const operations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Multiple goroutines performing operations
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			
			for j := 0; j < operations; j++ {
				key := id*operations + j
				
				// Set
				c.Set(key, key*2)
				
				// Get
				val, ok := c.Get(key)
				if ok && val != key*2 {
					t.Errorf("Goroutine %d: unexpected value %d for key %d", id, val, key)
				}
				
				// Sometimes delete
				if j%3 == 0 {
					c.Delete(key)
				}
			}
		}(i)
	}

	wg.Wait()

	// Size should be reasonable (some items deleted)
	size := c.Size()
	if size >= goroutines*operations {
		t.Errorf("Expected some deletions, but size is %d", size)
	}
}

func TestCacheConcurrentReadWrite(t *testing.T) {
	c := New[string, int](WithTTL[string, int](100 * time.Millisecond))
	defer c.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				c.Set("counter", i)
				i++
				time.Sleep(time.Microsecond)
			}
		}
	}()

	// Multiple reader goroutines
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					val, ok := c.Get("counter")
					if ok && val < 0 {
						t.Errorf("Reader %d: got negative value %d", id, val)
					}
					time.Sleep(time.Microsecond)
				}
			}
		}(i)
	}

	// Run for a short time
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestCacheTypeVariety(t *testing.T) {
	t.Run("struct values", func(t *testing.T) {
		type Person struct {
			Name string
			Age  int
		}

		c := New[string, Person]()
		defer c.Close()

		p1 := Person{Name: "Alice", Age: 30}
		c.Set("alice", p1)

		retrieved, ok := c.Get("alice")
		if !ok {
			t.Error("Failed to retrieve struct")
		}
		if retrieved.Name != p1.Name || retrieved.Age != p1.Age {
			t.Errorf("Retrieved struct doesn't match: got %+v, want %+v", retrieved, p1)
		}
	})

	t.Run("pointer values", func(t *testing.T) {
		c := New[string, *int]()
		defer c.Close()

		val := 42
		c.Set("ptr", &val)

		retrieved, ok := c.Get("ptr")
		if !ok {
			t.Error("Failed to retrieve pointer")
		}
		if *retrieved != 42 {
			t.Errorf("Retrieved pointer value doesn't match: got %d, want 42", *retrieved)
		}

		// Modify original
		val = 100
		retrieved2, _ := c.Get("ptr")
		if *retrieved2 != 100 {
			t.Error("Pointer value should reflect changes")
		}
	})

	t.Run("slice values", func(t *testing.T) {
		c := New[string, []int]()
		defer c.Close()

		slice := []int{1, 2, 3, 4, 5}
		c.Set("slice", slice)

		retrieved, ok := c.Get("slice")
		if !ok {
			t.Error("Failed to retrieve slice")
		}
		if len(retrieved) != len(slice) {
			t.Errorf("Retrieved slice length doesn't match: got %d, want %d", len(retrieved), len(slice))
		}
	})
}

func TestCacheEdgeCases(t *testing.T) {
	t.Run("zero TTL", func(t *testing.T) {
		c := New[string, string](WithTTL[string, string](0))
		defer c.Close()

		c.Set("key", "value")
		
		// Should not expire
		time.Sleep(10 * time.Millisecond)
		
		val, ok := c.Get("key")
		if !ok || val != "value" {
			t.Error("Item should not expire with zero TTL")
		}
	})

	t.Run("very short TTL", func(t *testing.T) {
		c := New[string, string](WithTTL[string, string](time.Nanosecond))
		defer c.Close()

		c.Set("key", "value")
		
		// Even with very short TTL, immediate get might succeed
		c.Get("key")
		
		// But after any delay, should be expired
		time.Sleep(time.Millisecond)
		_, ok := c.Get("key")
		if ok {
			t.Error("Item should expire with nanosecond TTL")
		}
	})

	t.Run("max size of 1", func(t *testing.T) {
		c := New[string, string](WithMaxSize[string, string](1))
		defer c.Close()

		c.Set("a", "1")
		c.Set("b", "2")

		// Only one item should exist
		if c.Size() != 1 {
			t.Errorf("Expected size 1, got %d", c.Size())
		}

		// Latest item should exist
		val, ok := c.Get("b")
		if !ok || val != "2" {
			t.Error("Latest item should exist")
		}

		// Previous item should be evicted
		_, ok = c.Get("a")
		if ok {
			t.Error("Previous item should be evicted")
		}
	})
}

// Benchmark tests

func BenchmarkCacheSet(b *testing.B) {
	c := New[int, int]()
	defer c.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set(i, i)
	}
}

func BenchmarkCacheGet(b *testing.B) {
	c := New[int, int]()
	defer c.Close()

	// Pre-populate
	for i := 0; i < 1000; i++ {
		c.Set(i, i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Get(i % 1000)
	}
}

func BenchmarkCacheSetWithTTL(b *testing.B) {
	c := New[int, int](WithTTL[int, int](time.Minute))
	defer c.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set(i, i)
	}
}

func BenchmarkCacheSetWithMaxSize(b *testing.B) {
	c := New[int, int](WithMaxSize[int, int](1000))
	defer c.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set(i, i)
	}
}

func BenchmarkCacheConcurrentSetGet(b *testing.B) {
	c := New[int, int]()
	defer c.Close()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			c.Set(i%1000, i)
			c.Get(i % 1000)
			i++
		}
	})
}