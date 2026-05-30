package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCacheKey(t *testing.T) {
	tests := []struct {
		runtime, profile, want string
	}{
		{"runsc", "npm", "runsc:npm"},
		{"", "npm", "runc:npm"},
		{"runc", "npm", "runc:npm"},
		{"runsc", "pnpm", "runsc:pnpm"},
	}
	for _, tt := range tests {
		got := cacheKey(tt.runtime, tt.profile)
		if got != tt.want {
			t.Errorf("cacheKey(%q, %q) = %q, want %q", tt.runtime, tt.profile, got, tt.want)
		}
	}
}

func TestCacheDataLoadSave(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "cache.json")

	// Write valid cache data.
	data := CacheData{
		Version: CacheVersion,
		Containers: map[string]*CachedContainer{
			"runsc:npm": {
				ContainerID: "abc123",
				Image:       "ghcr.io/test/image:latest",
				Runtime:     "runsc",
				Profile:     "npm",
				ImageDigest: "sha256:deadbeef",
				CreatedAt:   time.Now().Add(-1 * time.Hour),
				LastUsed:    time.Now(),
			},
		},
	}
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	// Load it back via a CacheManager (with nil Docker client since we're unit testing).
	cm := &CacheManager{
		dir:      dir,
		filePath: filePath,
	}
	if err := cm.load(); err != nil {
		t.Fatalf("load() failed: %v", err)
	}

	if cm.data.Version != CacheVersion {
		t.Errorf("version = %d, want %d", cm.data.Version, CacheVersion)
	}
	entry, ok := cm.data.Containers["runsc:npm"]
	if !ok {
		t.Fatal("expected runsc:npm entry")
	}
	if entry.ContainerID != "abc123" {
		t.Errorf("containerID = %q, want %q", entry.ContainerID, "abc123")
	}
	if entry.Image != "ghcr.io/test/image:latest" {
		t.Errorf("image = %q, want %q", entry.Image, "ghcr.io/test/image:latest")
	}

	// Test save.
	cm.data.Containers["runc:npm"] = &CachedContainer{
		ContainerID: "def456",
		Image:       "node:current-slim",
		Runtime:     "",
		Profile:     "npm",
		ImageDigest: "sha256:cafebabe",
		CreatedAt:   time.Now(),
		LastUsed:    time.Now(),
	}
	if err := cm.saveLocked(); err != nil {
		t.Fatalf("saveLocked() failed: %v", err)
	}

	// Reload and verify.
	cm2 := &CacheManager{
		dir:      dir,
		filePath: filePath,
	}
	if err := cm2.load(); err != nil {
		t.Fatalf("second load() failed: %v", err)
	}
	if len(cm2.data.Containers) != 2 {
		t.Errorf("expected 2 entries, got %d", len(cm2.data.Containers))
	}
	if _, ok := cm2.data.Containers["runc:npm"]; !ok {
		t.Fatal("expected runc:npm entry after save+reload")
	}
}

func TestCacheLoadMissingFile(t *testing.T) {
	dir := t.TempDir()
	cm := &CacheManager{
		dir:      dir,
		filePath: filepath.Join(dir, "nonexistent.json"),
	}
	err := cm.load()
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestCacheLoadInvalidVersion(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "cache.json")

	data := CacheData{
		Version:    999,
		Containers: map[string]*CachedContainer{},
	}
	raw, _ := json.Marshal(data)
	os.WriteFile(filePath, raw, 0o644)

	cm := &CacheManager{
		dir:      dir,
		filePath: filePath,
	}
	err := cm.load()
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestCacheSaveCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dir")
	filePath := filepath.Join(dir, "cache.json")

	cm := &CacheManager{
		dir:      dir,
		filePath: filePath,
		data: &CacheData{
			Version:    CacheVersion,
			Containers: map[string]*CachedContainer{},
		},
	}

	if err := cm.saveLocked(); err != nil {
		t.Fatalf("saveLocked() failed: %v", err)
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Fatal("expected cache file to exist")
	}
}

func TestEntries(t *testing.T) {
	cm := &CacheManager{
		data: &CacheData{
			Version: CacheVersion,
			Containers: map[string]*CachedContainer{
				"runsc:npm": {ContainerID: "abc", Profile: "npm"},
				"runc:bun":  {ContainerID: "def", Profile: "bun"},
			},
		},
	}

	entries := cm.Entries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Verify it's a copy (modifying shouldn't affect original).
	entries["runsc:npm"].ContainerID = "modified"
	if cm.data.Containers["runsc:npm"].ContainerID == "modified" {
		t.Fatal("Entries() should return a copy, not a reference")
	}
}

func TestResolveCacheDirFromEnv(t *testing.T) {
	t.Setenv(CacheDirEnvVar, "/tmp/goaudit-cache-env")
	got, err := ResolveCacheDir("")
	if err != nil {
		t.Fatalf("ResolveCacheDir returned error: %v", err)
	}
	if got != "/tmp/goaudit-cache-env" {
		t.Fatalf("expected env cache dir, got %q", got)
	}
}

func TestResolveCacheDirDefault(t *testing.T) {
	t.Setenv(CacheDirEnvVar, "")
	got, err := ResolveCacheDir("")
	if err != nil {
		t.Fatalf("ResolveCacheDir returned error: %v", err)
	}
	if !strings.HasSuffix(got, filepath.FromSlash(".goaudit/cache")) {
		t.Fatalf("expected default cache suffix, got %q", got)
	}
}

func TestTouchLastUsed(t *testing.T) {
	dir := t.TempDir()
	cm := &CacheManager{
		dir:      dir,
		filePath: filepath.Join(dir, "cache.json"),
		data: &CacheData{
			Version: CacheVersion,
			Containers: map[string]*CachedContainer{
				"runsc:npm": {
					ContainerID: "abc",
					Profile:     "npm",
					Runtime:     "runsc",
					LastUsed:    time.Now().Add(-24 * time.Hour),
				},
			},
		},
	}

	before := cm.data.Containers["runsc:npm"].LastUsed
	cm.TouchLastUsed("runsc", "npm")
	after := cm.data.Containers["runsc:npm"].LastUsed

	if !after.After(before) {
		t.Error("TouchLastUsed should update LastUsed to a later time")
	}
}
