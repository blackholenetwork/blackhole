package types

import (
	"testing"
	"time"
)

func TestUserTier(t *testing.T) {
	tests := []struct {
		tier     UserTier
		expected string
		priority int
	}{
		{TierFree, "free", 0},
		{TierNormal, "normal", 1},
		{TierAdvance, "advance", 2},
		{TierUltimate, "ultimate", 3},
		{UserTier(99), "unknown", 99}, // Invalid tier
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.tier.String(); got != tt.expected {
				t.Errorf("UserTier.String() = %v, want %v", got, tt.expected)
			}
			if got := tt.tier.Priority(); got != tt.priority {
				t.Errorf("UserTier.Priority() = %v, want %v", got, tt.priority)
			}
		})
	}
}

func TestByteSize(t *testing.T) {
	tests := []struct {
		size     ByteSize
		expected string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{1023, "1023 B"},
		{KB, "1.00 KB"},
		{KB + 512, "1.50 KB"},
		{MB, "1.00 MB"},
		{MB*2 + KB*512, "2.50 MB"},
		{GB, "1.00 GB"},
		{GB*3 + MB*256, "3.25 GB"},
		{TB, "1.00 TB"},
		{TB*2 + GB*512, "2.50 TB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.size.String(); got != tt.expected {
				t.Errorf("ByteSize.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHash(t *testing.T) {
	t.Run("String representation", func(t *testing.T) {
		hashBytes := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
		hash := Hash(hashBytes)

		expected := "0123456789abcdef"
		if got := hash.String(); got != expected {
			t.Errorf("Hash.String() = %v, want %v", got, expected)
		}
	})

	t.Run("IsZero", func(t *testing.T) {
		emptyHash := Hash{}
		if !emptyHash.IsZero() {
			t.Error("Empty hash should be zero")
		}

		nonEmptyHash := Hash([]byte{0x00})
		if nonEmptyHash.IsZero() {
			t.Error("Non-empty hash should not be zero")
		}
	})

	t.Run("nil hash", func(t *testing.T) {
		var nilHash Hash
		if !nilHash.IsZero() {
			t.Error("Nil hash should be zero")
		}
		if nilHash.String() != "" {
			t.Error("Nil hash string should be empty")
		}
	})
}

func TestTimeRange(t *testing.T) {
	now := time.Now()
	start := now
	end := now.Add(2 * time.Hour)

	tr := TimeRange{Start: start, End: end}

	t.Run("Duration", func(t *testing.T) {
		expected := 2 * time.Hour
		if got := tr.Duration(); got != expected {
			t.Errorf("TimeRange.Duration() = %v, want %v", got, expected)
		}
	})

	t.Run("Contains", func(t *testing.T) {
		tests := []struct {
			name     string
			time     time.Time
			contains bool
		}{
			{"before start", start.Add(-1 * time.Hour), false},
			{"at start", start, true},
			{"in middle", start.Add(1 * time.Hour), true},
			{"at end", end, true},
			{"after end", end.Add(1 * time.Hour), false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := tr.Contains(tt.time); got != tt.contains {
					t.Errorf("TimeRange.Contains() = %v, want %v", got, tt.contains)
				}
			})
		}
	})

	t.Run("Overlaps", func(t *testing.T) {
		tests := []struct {
			name     string
			other    TimeRange
			overlaps bool
		}{
			{
				"completely before",
				TimeRange{Start: start.Add(-3 * time.Hour), End: start.Add(-1 * time.Hour)},
				false,
			},
			{
				"touches start",
				TimeRange{Start: start.Add(-1 * time.Hour), End: start},
				false,
			},
			{
				"overlaps start",
				TimeRange{Start: start.Add(-1 * time.Hour), End: start.Add(1 * time.Hour)},
				true,
			},
			{
				"contained within",
				TimeRange{Start: start.Add(30 * time.Minute), End: start.Add(90 * time.Minute)},
				true,
			},
			{
				"contains",
				TimeRange{Start: start.Add(-1 * time.Hour), End: end.Add(1 * time.Hour)},
				true,
			},
			{
				"overlaps end",
				TimeRange{Start: end.Add(-1 * time.Hour), End: end.Add(1 * time.Hour)},
				true,
			},
			{
				"touches end",
				TimeRange{Start: end, End: end.Add(1 * time.Hour)},
				false,
			},
			{
				"completely after",
				TimeRange{Start: end.Add(1 * time.Hour), End: end.Add(3 * time.Hour)},
				false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := tr.Overlaps(tt.other); got != tt.overlaps {
					t.Errorf("TimeRange.Overlaps() = %v, want %v", got, tt.overlaps)
				}
			})
		}
	})
}

func TestMetadata(t *testing.T) {
	m := make(Metadata)

	t.Run("Get/Set", func(t *testing.T) {
		// Set values
		m.Set("string", "value")
		m.Set("int", 42)
		m.Set("float", 3.14)
		m.Set("bool", true)

		// Get values
		if val, ok := m.Get("string"); !ok || val != "value" {
			t.Errorf("Get string failed: %v, %v", val, ok)
		}

		if val, ok := m.Get("nonexistent"); ok {
			t.Errorf("Get nonexistent should return false, got %v", val)
		}
	})

	t.Run("GetString", func(t *testing.T) {
		m.Set("string", "hello")
		m.Set("number", 123)

		if val, ok := m.GetString("string"); !ok || val != "hello" {
			t.Errorf("GetString failed: %v, %v", val, ok)
		}

		if _, ok := m.GetString("number"); ok {
			t.Error("GetString on non-string should return false")
		}

		if _, ok := m.GetString("nonexistent"); ok {
			t.Error("GetString on nonexistent should return false")
		}
	})

	t.Run("GetInt", func(t *testing.T) {
		m.Set("int", 42)
		m.Set("int64", int64(100))
		m.Set("float64", float64(3.14))
		m.Set("string", "not a number")

		tests := []struct {
			key      string
			expected int
			ok       bool
		}{
			{"int", 42, true},
			{"int64", 100, true},
			{"float64", 3, true}, // Truncated
			{"string", 0, false},
			{"nonexistent", 0, false},
		}

		for _, tt := range tests {
			t.Run(tt.key, func(t *testing.T) {
				val, ok := m.GetInt(tt.key)
				if ok != tt.ok {
					t.Errorf("GetInt(%s) ok = %v, want %v", tt.key, ok, tt.ok)
				}
				if ok && val != tt.expected {
					t.Errorf("GetInt(%s) = %v, want %v", tt.key, val, tt.expected)
				}
			})
		}
	})

	t.Run("Delete", func(t *testing.T) {
		m.Set("temp", "value")
		if _, ok := m.Get("temp"); !ok {
			t.Error("Value should exist before delete")
		}

		m.Delete("temp")
		if _, ok := m.Get("temp"); ok {
			t.Error("Value should not exist after delete")
		}
	})

	t.Run("Clone", func(t *testing.T) {
		original := make(Metadata)
		original.Set("key1", "value1")
		original.Set("key2", 42)

		cloned := original.Clone()

		// Verify cloned has same values
		if val, _ := cloned.GetString("key1"); val != "value1" {
			t.Error("Clone should have same string value")
		}
		if val, _ := cloned.GetInt("key2"); val != 42 {
			t.Error("Clone should have same int value")
		}

		// Verify modifications don't affect original
		cloned.Set("key1", "modified")
		cloned.Set("key3", "new")

		if val, _ := original.GetString("key1"); val != "value1" {
			t.Error("Original should not be affected by clone modification")
		}
		if _, ok := original.Get("key3"); ok {
			t.Error("Original should not have new keys from clone")
		}
	})
}

func TestPagination(t *testing.T) {
	t.Run("TotalPages", func(t *testing.T) {
		tests := []struct {
			page     Pagination
			expected int
		}{
			{Pagination{Page: 1, PerPage: 10, Total: 0}, 0},
			{Pagination{Page: 1, PerPage: 10, Total: 1}, 1},
			{Pagination{Page: 1, PerPage: 10, Total: 10}, 1},
			{Pagination{Page: 1, PerPage: 10, Total: 11}, 2},
			{Pagination{Page: 1, PerPage: 10, Total: 100}, 10},
			{Pagination{Page: 1, PerPage: 0, Total: 100}, 0}, // Division by zero protection
		}

		for _, tt := range tests {
			t.Run("", func(t *testing.T) {
				if got := tt.page.TotalPages(); got != tt.expected {
					t.Errorf("TotalPages() = %v, want %v for %+v", got, tt.expected, tt.page)
				}
			})
		}
	})

	t.Run("Offset", func(t *testing.T) {
		tests := []struct {
			page     Pagination
			expected int
		}{
			{Pagination{Page: 0, PerPage: 10}, 0},  // Invalid page
			{Pagination{Page: 1, PerPage: 10}, 0},
			{Pagination{Page: 2, PerPage: 10}, 10},
			{Pagination{Page: 3, PerPage: 10}, 20},
			{Pagination{Page: 5, PerPage: 25}, 100},
		}

		for _, tt := range tests {
			t.Run("", func(t *testing.T) {
				if got := tt.page.Offset(); got != tt.expected {
					t.Errorf("Offset() = %v, want %v for page %d", got, tt.expected, tt.page.Page)
				}
			})
		}
	})

	t.Run("HasNext", func(t *testing.T) {
		tests := []struct {
			page     Pagination
			expected bool
		}{
			{Pagination{Page: 1, PerPage: 10, Total: 5}, false},   // Single page
			{Pagination{Page: 1, PerPage: 10, Total: 15}, true},   // Has next
			{Pagination{Page: 2, PerPage: 10, Total: 15}, false},  // Last page
			{Pagination{Page: 3, PerPage: 10, Total: 15}, false},  // Beyond last
		}

		for _, tt := range tests {
			t.Run("", func(t *testing.T) {
				if got := tt.page.HasNext(); got != tt.expected {
					t.Errorf("HasNext() = %v, want %v for %+v", got, tt.expected, tt.page)
				}
			})
		}
	})

	t.Run("HasPrev", func(t *testing.T) {
		tests := []struct {
			page     Pagination
			expected bool
		}{
			{Pagination{Page: 0, PerPage: 10, Total: 50}, false},  // Invalid page
			{Pagination{Page: 1, PerPage: 10, Total: 50}, false},  // First page
			{Pagination{Page: 2, PerPage: 10, Total: 50}, true},   // Has previous
			{Pagination{Page: 5, PerPage: 10, Total: 50}, true},   // Last page
		}

		for _, tt := range tests {
			t.Run("", func(t *testing.T) {
				if got := tt.page.HasPrev(); got != tt.expected {
					t.Errorf("HasPrev() = %v, want %v for page %d", got, tt.expected, tt.page.Page)
				}
			})
		}
	})
}

func TestTypeAliases(t *testing.T) {
	// Just verify the type aliases work as expected
	var nodeID NodeID = "node123"
	var fileID FileID = "file456"
	var chunkID ChunkID = "chunk789"
	var userID UserID = "user012"
	var jobID JobID = "job345"

	// Should be able to convert to string
	_ = string(nodeID)
	_ = string(fileID)
	_ = string(chunkID)
	_ = string(userID)
	_ = string(jobID)

	// Constants should have expected values
	if ResourceTypeStorage != "storage" {
		t.Errorf("ResourceTypeStorage = %v, want 'storage'", ResourceTypeStorage)
	}
	if JobTypeCompute != "compute" {
		t.Errorf("JobTypeCompute = %v, want 'compute'", JobTypeCompute)
	}
	if StatusPending != "pending" {
		t.Errorf("StatusPending = %v, want 'pending'", StatusPending)
	}
}

// Benchmark tests

func BenchmarkByteSizeString(b *testing.B) {
	size := ByteSize(1234567890)
	for i := 0; i < b.N; i++ {
		_ = size.String()
	}
}

func BenchmarkHashString(b *testing.B) {
	hash := Hash([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
	for i := 0; i < b.N; i++ {
		_ = hash.String()
	}
}

func BenchmarkMetadataOperations(b *testing.B) {
	m := make(Metadata)

	b.Run("Set", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.Set("key", i)
		}
	})

	b.Run("Get", func(b *testing.B) {
		m.Set("key", "value")
		for i := 0; i < b.N; i++ {
			_, _ = m.Get("key")
		}
	})

	b.Run("Clone", func(b *testing.B) {
		for k := 0; k < 10; k++ {
			m.Set(string(rune('a'+k)), k)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = m.Clone()
		}
	})
}

func BenchmarkPaginationTotalPages(b *testing.B) {
	p := Pagination{Page: 5, PerPage: 20, Total: 1000}
	for i := 0; i < b.N; i++ {
		_ = p.TotalPages()
	}
}
