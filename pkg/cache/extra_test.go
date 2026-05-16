package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpen_ParentDirCreationFailure(t *testing.T) {
	// Make a *file* and try to use it as a parent directory. MkdirAll
	// should fail because the path component is not a directory.
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Open(filepath.Join(blocker, "child", "cache.db"))
	if err == nil {
		t.Fatal("expected Open to fail with non-dir in the path")
	}
}

func TestOpen_EmptyPathUsesDefault(t *testing.T) {
	// Redirect XDG_CACHE_HOME so the default lands in our temp dir.
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	c, err := Open("")
	if err != nil {
		t.Fatalf("Open default: %v", err)
	}
	defer c.Close()
	if c.Path() == "" || filepath.Base(c.Path()) != "cache.db" {
		t.Errorf("unexpected default path: %s", c.Path())
	}
}

func TestPurge_NoExpiredRows(t *testing.T) {
	c := openTemp(t)
	if err := c.Set("k", []byte("v"), time.Hour); err != nil {
		t.Fatal(err)
	}
	n, err := c.Purge()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("nothing expired: want 0, got %d", n)
	}
}

func TestStats_MixedEntries(t *testing.T) {
	c := openTemp(t)
	base := time.Now()
	c.now = func() time.Time { return base }
	_ = c.Set("a", []byte("x"), time.Hour)
	_ = c.Set("b", []byte("x"), time.Second)
	c.now = func() time.Time { return base.Add(2 * time.Second) }
	total, expired, err := c.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Errorf("total: want 2, got %d", total)
	}
	if expired != 1 {
		t.Errorf("expired: want 1, got %d", expired)
	}
}

func TestSplitKey_Variants(t *testing.T) {
	tech, target := splitKey("crtsh|example.com|abc")
	if tech != "crtsh" || target != "example.com" {
		t.Errorf("structured key: got tech=%q target=%q", tech, target)
	}
	tech, target = splitKey("loose-key-no-delims")
	if tech != "loose-key-no-delims" || target != "" {
		t.Errorf("loose key: got tech=%q target=%q", tech, target)
	}
	tech, target = splitKey("a|b")
	if tech != "a" || target != "b" {
		t.Errorf("two parts: got tech=%q target=%q", tech, target)
	}
}

func TestSet_ZeroTTLImmediatelyExpired(t *testing.T) {
	c := openTemp(t)
	// A non-positive TTL is permitted (the docs say so); the row should
	// immediately be considered stale.
	if err := c.Set("k", []byte("v"), 0); err != nil {
		t.Fatal(err)
	}
	_, hit, err := c.Get("k")
	if err != nil {
		t.Fatal(err)
	}
	if hit {
		t.Error("zero-TTL entry should not hit")
	}
}
