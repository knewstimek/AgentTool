package memtool

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	scanIdleTimeout    = 10 * time.Minute
	scanMaxSessions    = 3
	scanReaperInterval = 30 * time.Second
)

// scanMatch represents a matched address with its previous value.
type scanMatch struct {
	Address  uint64
	PrevData []byte
}

// undoState stores a previous match store for undo support.
type undoState struct {
	store       *matchStore
	snapshot    *memorySnapshot
	unknownScan bool
}

// scanSession holds state for an ongoing memory scan workflow.
// All field access must be protected by mu, except immutable fields (id, pid, valueType, valueSize, endian, createdAt).
type scanSession struct {
	mu sync.Mutex

	id        string
	pid       int
	valueType ValueType
	valueSize int
	endian    binary.ByteOrder

	reader      ProcessReader
	store       *matchStore       // hybrid in-memory / disk-backed match storage
	snapshot    *memorySnapshot
	unknownScan bool              // true = initial scan was unknown value (snapshot-based)

	// Undo stack — up to 5 previous states
	undoStack []undoState

	matchCount int

	// refcount tracks active operations. Reaper skips sessions with refs > 0.
	refs int32 // accessed atomically

	createdAt time.Time
	lastUsed  time.Time
}

// acquire increments the refcount. Must be called after pool.get().
func (s *scanSession) acquire() { atomic.AddInt32(&s.refs, 1) }

// release decrements the refcount.
func (s *scanSession) release() { atomic.AddInt32(&s.refs, -1) }

// inUse returns true if any operation is active on this session.
func (s *scanSession) inUse() bool { return atomic.LoadInt32(&s.refs) > 0 }

func (s *scanSession) close() {
	// Caller must ensure no concurrent access (pool.mu or sole owner)
	if s.reader != nil {
		s.reader.Close()
		s.reader = nil
	}
	if s.store != nil {
		s.store.Close()
		s.store = nil
	}
	if s.snapshot != nil {
		s.snapshot.Close()
		s.snapshot = nil
	}
	for i := range s.undoStack {
		if s.undoStack[i].store != nil {
			s.undoStack[i].store.Close()
		}
		if s.undoStack[i].snapshot != nil {
			s.undoStack[i].snapshot.Close()
		}
	}
	s.undoStack = nil
}

// pushUndo saves current match store for undo. Caller must hold s.mu.
// The current store pointer is saved; caller must assign a new store after this.
func (s *scanSession) pushUndo() {
	const maxUndo = 5

	state := undoState{
		store:       s.store,
		unknownScan: s.unknownScan,
	}
	s.undoStack = append(s.undoStack, state)

	if len(s.undoStack) > maxUndo {
		old := s.undoStack[0]
		if old.store != nil {
			old.store.Close()
		}
		if old.snapshot != nil {
			old.snapshot.Close()
		}
		// Copy forward to avoid underlying array memory leak (audit M2)
		newStack := make([]undoState, len(s.undoStack)-1)
		copy(newStack, s.undoStack[1:])
		s.undoStack = newStack
	}
}

// popUndo restores previous match state. Caller must hold s.mu.
func (s *scanSession) popUndo() bool {
	if len(s.undoStack) == 0 {
		return false
	}

	last := s.undoStack[len(s.undoStack)-1]
	s.undoStack = s.undoStack[:len(s.undoStack)-1]

	// Close current store before restoring
	if s.store != nil {
		s.store.Close()
	}
	s.store = last.store
	s.unknownScan = last.unknownScan
	if s.store != nil {
		s.matchCount = s.store.Count()
	} else {
		s.matchCount = 0
	}
	if last.snapshot != nil {
		if s.snapshot != nil {
			s.snapshot.Close()
		}
		s.snapshot = last.snapshot
	}
	return true
}

type scanPool struct {
	mu       sync.Mutex
	sessions map[string]*scanSession
}

var pool = &scanPool{
	sessions: make(map[string]*scanSession),
}

func init() {
	go pool.reaper()
}

func (p *scanPool) get(id string) (*scanSession, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.sessions[id]
	if ok {
		s.lastUsed = time.Now()
		s.acquire() // caller must call release() when done
	}
	return s, ok
}

func (p *scanPool) add(s *scanSession) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.sessions[s.id]; exists {
		return fmt.Errorf("session %q already exists", s.id)
	}
	if len(p.sessions) >= scanMaxSessions {
		p.evictOldestLocked()
	}
	p.sessions[s.id] = s
	return nil
}

func (p *scanPool) remove(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.sessions[id]
	if !ok {
		return false
	}
	s.close()
	delete(p.sessions, id)
	return true
}

// reaper periodically removes idle sessions.
// Skips sessions that are currently in use (refs > 0) to avoid
// closing handles while an operation is reading/writing. (audit C2)
func (p *scanPool) reaper() {
	ticker := time.NewTicker(scanReaperInterval)
	defer ticker.Stop()
	for range ticker.C {
		p.mu.Lock()
		now := time.Now()
		for id, s := range p.sessions {
			if now.Sub(s.lastUsed) > scanIdleTimeout && !s.inUse() {
				s.close()
				delete(p.sessions, id)
			}
		}
		p.mu.Unlock()
	}
}

func (p *scanPool) evictOldestLocked() {
	var oldestID string
	var oldestTime time.Time
	for id, s := range p.sessions {
		// Don't evict sessions that are in use
		if s.inUse() {
			continue
		}
		if oldestID == "" || s.lastUsed.Before(oldestTime) {
			oldestID = id
			oldestTime = s.lastUsed
		}
	}
	if oldestID != "" {
		if s, ok := p.sessions[oldestID]; ok {
			s.close()
		}
		delete(p.sessions, oldestID)
	}
}

func newSessionID() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	randomBytes := make([]byte, 12)
	if _, err := rand.Read(randomBytes); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	b := make([]byte, 12)
	for i := range b {
		b[i] = chars[randomBytes[i]%byte(len(chars))]
	}
	return string(b)
}
