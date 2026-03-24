package cache

import (
	"sync"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	c := New(1 * time.Hour)
	if c == nil {
		t.Fatal("expected non-nil cache")
	}
	if c.ttl != 1*time.Hour {
		t.Fatalf("expected TTL 1h, got %v", c.ttl)
	}
	if c.Size() != 0 {
		t.Fatalf("expected empty cache, got size %d", c.Size())
	}
}

func TestShouldScan_EmptyDigest(t *testing.T) {
	c := New(1 * time.Hour)
	// Empty digest should always return true
	if !c.ShouldScan("") {
		t.Fatal("expected ShouldScan('') to return true")
	}
}

func TestShouldScan_UnknownDigest(t *testing.T) {
	c := New(1 * time.Hour)
	if !c.ShouldScan("sha256:abc123") {
		t.Fatal("expected ShouldScan for unknown digest to return true")
	}
}

func TestMarkScanned_ThenShouldScanReturnsFalse(t *testing.T) {
	c := New(1 * time.Hour)
	digest := "sha256:abc123def456"

	c.MarkScanned(digest)

	if c.ShouldScan(digest) {
		t.Fatal("expected ShouldScan to return false after MarkScanned")
	}
	if c.Size() != 1 {
		t.Fatalf("expected size 1, got %d", c.Size())
	}
}

func TestMarkScanned_EmptyDigestIgnored(t *testing.T) {
	c := New(1 * time.Hour)
	c.MarkScanned("")
	if c.Size() != 0 {
		t.Fatalf("expected size 0 after marking empty digest, got %d", c.Size())
	}
}

func TestShouldScan_ExpiredEntry(t *testing.T) {
	c := New(10 * time.Millisecond)
	digest := "sha256:expired"

	c.MarkScanned(digest)
	if c.ShouldScan(digest) {
		t.Fatal("expected ShouldScan to return false immediately after marking")
	}

	time.Sleep(20 * time.Millisecond)

	if !c.ShouldScan(digest) {
		t.Fatal("expected ShouldScan to return true after TTL expiry")
	}
}

func TestCleanup_RemovesExpiredEntries(t *testing.T) {
	c := New(10 * time.Millisecond)

	c.MarkScanned("sha256:old1")
	c.MarkScanned("sha256:old2")
	time.Sleep(20 * time.Millisecond)

	// Add a fresh entry
	c.MarkScanned("sha256:fresh")

	c.Cleanup()

	if c.Size() != 1 {
		t.Fatalf("expected 1 entry after cleanup, got %d", c.Size())
	}
	if !c.ShouldScan("sha256:old1") {
		t.Fatal("expected old1 to be cleaned up")
	}
	if c.ShouldScan("sha256:fresh") {
		t.Fatal("expected fresh to still be cached")
	}
}

func TestCleanup_EmptyCache(t *testing.T) {
	c := New(1 * time.Hour)
	c.Cleanup() // should not panic
	if c.Size() != 0 {
		t.Fatalf("expected size 0, got %d", c.Size())
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New(1 * time.Hour)
	var wg sync.WaitGroup

	// Concurrent writes
	for i := range 100 {
		wg.Go(func() {
			digest := "sha256:" + string(rune('a'+i%26))
			c.MarkScanned(digest)
			c.ShouldScan(digest)
		})
	}

	// Concurrent reads + cleanup
	for range 10 {
		wg.Go(func() {
			c.Size()
			c.Cleanup()
		})
	}

	wg.Wait()
	// No race/deadlock = pass
}

func TestMultipleMarks_SameDigest(t *testing.T) {
	c := New(50 * time.Millisecond)
	digest := "sha256:remark"

	c.MarkScanned(digest)
	time.Sleep(30 * time.Millisecond)

	// Re-mark should refresh the timestamp
	c.MarkScanned(digest)
	time.Sleep(30 * time.Millisecond)

	// 60ms total, but remarked at 30ms, so only 30ms since last mark < 50ms TTL
	if c.ShouldScan(digest) {
		t.Fatal("expected ShouldScan to return false after re-marking")
	}
}
