package common

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const (
	RawOutputTTL        = 30 * time.Minute
	maxRawOutputEntries = 64
	maxRawOutputBytes   = 4 * 1024 * 1024
)

// RawOutputRecord is a bounded command output retained only when the displayed
// form was compacted. Records are process-local and expire automatically.
type RawOutputRecord struct {
	ID            string
	Source        string
	Content       string
	Truncated     bool
	OriginalBytes int64
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

type rawOutputStore struct {
	mu         sync.Mutex
	entries    map[string]RawOutputRecord
	order      []string
	totalBytes int
	maxEntries int
	maxBytes   int
	ttl        time.Duration
}

func newRawOutputStore(maxEntries, maxBytes int, ttl time.Duration) *rawOutputStore {
	return &rawOutputStore{
		entries:    make(map[string]RawOutputRecord),
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		ttl:        ttl,
	}
}

var commandRawOutputs = newRawOutputStore(maxRawOutputEntries, maxRawOutputBytes, RawOutputTTL)

// PreserveRawOutput stores already-bounded output and returns an opaque lookup
// ID. An empty ID means the record could not be stored.
func PreserveRawOutput(source, content string, truncated bool, originalBytes int64) string {
	return commandRawOutputs.put(source, content, truncated, originalBytes, time.Now())
}

// LoadRawOutput returns a non-expired preserved command output.
func LoadRawOutput(id string) (RawOutputRecord, bool) {
	return commandRawOutputs.get(id, time.Now())
}

func (s *rawOutputStore) put(source, content string, truncated bool, originalBytes int64, now time.Time) string {
	if content == "" || s.maxEntries <= 0 || s.maxBytes <= 0 || len(content) > s.maxBytes {
		return ""
	}
	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		return ""
	}
	id := "out_" + hex.EncodeToString(idBytes)
	record := RawOutputRecord{
		ID: id, Source: source, Content: content, Truncated: truncated,
		OriginalBytes: originalBytes, CreatedAt: now, ExpiresAt: now.Add(s.ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeExpiredLocked(now)
	for len(s.order) >= s.maxEntries || s.totalBytes+len(content) > s.maxBytes {
		if len(s.order) == 0 {
			return ""
		}
		s.removeLocked(s.order[0])
	}
	s.entries[id] = record
	s.order = append(s.order, id)
	s.totalBytes += len(content)
	return id
}

func (s *rawOutputStore) get(id string, now time.Time) (RawOutputRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeExpiredLocked(now)
	record, ok := s.entries[id]
	return record, ok
}

func (s *rawOutputStore) removeExpiredLocked(now time.Time) {
	for len(s.order) > 0 {
		record, ok := s.entries[s.order[0]]
		if ok && now.Before(record.ExpiresAt) {
			break
		}
		s.removeLocked(s.order[0])
	}
}

func (s *rawOutputStore) removeLocked(id string) {
	record, ok := s.entries[id]
	if ok {
		s.totalBytes -= len(record.Content)
		delete(s.entries, id)
	}
	for i, orderedID := range s.order {
		if orderedID == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
}
