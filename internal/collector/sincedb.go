package collector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SinceDB tracks file read positions for resumption after restart.
type SinceDB struct {
	path    string
	mu      sync.RWMutex
	entries map[string]*SinceDBEntry
	dirty   bool
}

// SinceDBEntry represents a tracked file position.
type SinceDBEntry struct {
	Path     string    `json:"path"`
	Inode    uint64    `json:"inode"`
	Device   uint64    `json:"device"`
	Offset   int64     `json:"offset"`
	Modified time.Time `json:"modified"`
}

// NewSinceDB creates a new SinceDB instance.
func NewSinceDB(path string) (*SinceDB, error) {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating sincedb directory: %w", err)
	}

	return &SinceDB{
		path:    path,
		entries: make(map[string]*SinceDBEntry),
	}, nil
}

// Load loads entries from disk.
func (s *SinceDB) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Fresh start, no sincedb file yet
		}
		return fmt.Errorf("reading sincedb: %w", err)
	}

	var entries map[string]*SinceDBEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("parsing sincedb: %w", err)
	}

	s.entries = entries
	s.dirty = false
	return nil
}

// Save persists entries to disk.
func (s *SinceDB) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.dirty {
		return nil // Nothing to save
	}

	data, err := json.MarshalIndent(s.entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling sincedb: %w", err)
	}

	// Write to temp file first, then rename for atomicity
	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("writing sincedb: %w", err)
	}

	if err := os.Rename(tmpPath, s.path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("renaming sincedb: %w", err)
	}

	s.dirty = false
	return nil
}

// GetOffset returns the stored offset for a file, or -1 if not found.
// The inode and device are used to identify the file even after rotation.
func (s *SinceDB) GetOffset(path string, inode, device uint64) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := s.fileKey(path, inode, device)
	if entry, ok := s.entries[key]; ok {
		return entry.Offset
	}
	return -1
}

// SetOffset updates the stored offset for a file.
func (s *SinceDB) SetOffset(path string, inode, device uint64, offset int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := s.fileKey(path, inode, device)
	s.entries[key] = &SinceDBEntry{
		Path:     path,
		Inode:    inode,
		Device:   device,
		Offset:   offset,
		Modified: time.Now(),
	}
	s.dirty = true
}

// RemoveStale removes entries older than maxAge.
func (s *SinceDB) RemoveStale(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for key, entry := range s.entries {
		if entry.Modified.Before(cutoff) {
			delete(s.entries, key)
			s.dirty = true
		}
	}
}

// fileKey generates a unique key for a file based on inode and device.
func (s *SinceDB) fileKey(path string, inode, device uint64) string {
	return fmt.Sprintf("%s|%d|%d", path, inode, device)
}

