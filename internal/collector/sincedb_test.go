package collector

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSinceDB(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "sincedb-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "sincedb.json")

	// Create sincedb
	sdb, err := NewSinceDB(dbPath)
	if err != nil {
		t.Fatalf("NewSinceDB() error = %v", err)
	}

	// Load (should succeed even if file doesn't exist)
	if err := sdb.Load(); err != nil {
		t.Errorf("Load() error = %v", err)
	}

	// Test GetOffset for non-existent file
	offset := sdb.GetOffset("/var/log/test.log", 12345, 1)
	if offset != -1 {
		t.Errorf("GetOffset() for non-existent = %d, want -1", offset)
	}

	// Set offset
	sdb.SetOffset("/var/log/test.log", 12345, 1, 1000)

	// Get offset
	offset = sdb.GetOffset("/var/log/test.log", 12345, 1)
	if offset != 1000 {
		t.Errorf("GetOffset() = %d, want 1000", offset)
	}

	// Save
	if err := sdb.Save(); err != nil {
		t.Errorf("Save() error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Save() did not create file")
	}

	// Create new sincedb instance and load
	sdb2, err := NewSinceDB(dbPath)
	if err != nil {
		t.Fatalf("NewSinceDB() error = %v", err)
	}

	if err := sdb2.Load(); err != nil {
		t.Errorf("Load() error = %v", err)
	}

	// Verify offset persisted
	offset = sdb2.GetOffset("/var/log/test.log", 12345, 1)
	if offset != 1000 {
		t.Errorf("GetOffset() after load = %d, want 1000", offset)
	}
}

func TestSinceDBRemoveStale(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sincedb-stale-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "sincedb.json")
	sdb, err := NewSinceDB(dbPath)
	if err != nil {
		t.Fatalf("NewSinceDB() error = %v", err)
	}

	// Add entries
	sdb.SetOffset("/var/log/old.log", 111, 1, 100)
	sdb.SetOffset("/var/log/new.log", 222, 1, 200)

	// Manually modify the old entry's timestamp
	sdb.mu.Lock()
	key := sdb.fileKey("/var/log/old.log", 111, 1)
	if entry, ok := sdb.entries[key]; ok {
		entry.Modified = time.Now().Add(-48 * time.Hour) // 2 days ago
	}
	sdb.mu.Unlock()

	// Remove stale entries (older than 24 hours)
	sdb.RemoveStale(24 * time.Hour)

	// Verify old entry removed
	offset := sdb.GetOffset("/var/log/old.log", 111, 1)
	if offset != -1 {
		t.Errorf("Stale entry not removed, offset = %d", offset)
	}

	// Verify new entry still exists
	offset = sdb.GetOffset("/var/log/new.log", 222, 1)
	if offset != 200 {
		t.Errorf("New entry was incorrectly removed, offset = %d", offset)
	}
}

func TestSinceDBDirty(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sincedb-dirty-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "sincedb.json")
	sdb, err := NewSinceDB(dbPath)
	if err != nil {
		t.Fatalf("NewSinceDB() error = %v", err)
	}

	// Save without changes (should not create file)
	if err := sdb.Save(); err != nil {
		t.Errorf("Save() error = %v", err)
	}

	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Error("Save() created file when not dirty")
	}

	// Make a change
	sdb.SetOffset("/var/log/test.log", 12345, 1, 500)

	// Save with changes
	if err := sdb.Save(); err != nil {
		t.Errorf("Save() error = %v", err)
	}

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Save() did not create file when dirty")
	}
}
