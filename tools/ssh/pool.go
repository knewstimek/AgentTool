package ssh

import (
	"fmt"
	"net"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

const (
	defaultIdleTimeout = 30 * time.Minute
	maxSessions        = 20
	reaperInterval     = 60 * time.Second
)

type sessionEntry struct {
	client      *gossh.Client
	agentConn   net.Conn // SSH agent socket; nil if not used
	jumpCleanup func()   // closes jump host resources; nil if no proxy
	key         string
	createdAt   time.Time
	lastUsed    time.Time
}

// close releases all resources held by this session entry.
func (e *sessionEntry) close() {
	e.client.Close()
	if e.agentConn != nil {
		e.agentConn.Close()
	}
	if e.jumpCleanup != nil {
		e.jumpCleanup()
	}
}

// dialResult holds the result of a dial operation for pool insertion.
type dialResult struct {
	client      *gossh.Client
	agentConn   net.Conn   // SSH agent socket; nil if not used
	jumpCleanup func()     // closes jump host client + its agent conn; nil if no proxy
}

type sessionPool struct {
	mu       sync.Mutex
	sessions map[string]*sessionEntry
}

var pool = &sessionPool{
	sessions: make(map[string]*sessionEntry),
}

func init() {
	go pool.reaper()
}

// sessionKey returns a unique key for a host:port:user combination.
func sessionKey(host string, port int, user string) string {
	return fmt.Sprintf("%s:%d:%s", host, port, user)
}

// getOrCreate returns an existing session or creates a new one using dialFn.
// dialFn is called WITHOUT holding the pool mutex to avoid blocking other
// operations during network I/O (up to 10s dial timeout). A double-check
// pattern prevents duplicate connections when concurrent goroutines dial
// the same host.
func (p *sessionPool) getOrCreate(key string, dialFn func() (*dialResult, error)) (*gossh.Client, bool, error) {
	p.mu.Lock()

	// Check existing session
	if entry, ok := p.sessions[key]; ok {
		client := entry.client
		p.mu.Unlock()

		// Keepalive check WITHOUT holding the lock — prevents a slow or
		// half-open connection from blocking the entire session pool.
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		if err == nil {
			p.mu.Lock()
			// Re-verify entry wasn't replaced/removed while unlocked.
			// If another goroutine closed this client, we must not return it.
			if e, ok := p.sessions[key]; ok && e.client == client {
				e.lastUsed = time.Now()
				p.mu.Unlock()
				return client, false, nil
			}
			p.mu.Unlock()
			// Entry was replaced/removed — fall through to dial new connection
		}

		// Connection dead — clean up under lock
		p.mu.Lock()
		if e, ok := p.sessions[key]; ok && e.client == client {
			e.close()
			delete(p.sessions, key)
		}
		if len(p.sessions) >= maxSessions {
			p.evictOldestLocked()
		}
		p.mu.Unlock()
	} else {
		// Evict oldest if at capacity
		if len(p.sessions) >= maxSessions {
			p.evictOldestLocked()
		}
		p.mu.Unlock()
	}

	// Dial WITHOUT holding the lock — avoids blocking the entire pool
	// during network I/O (can take up to dialTimeout = 10s).
	dr, err := dialFn()
	if err != nil {
		return nil, false, err
	}

	// Re-acquire lock and double-check: another goroutine may have created
	// a session for the same key while we were dialing.
	p.mu.Lock()
	defer p.mu.Unlock()

	if entry, ok := p.sessions[key]; ok {
		// Another goroutine won the race — discard our connection
		dr.client.Close()
		if dr.agentConn != nil {
			dr.agentConn.Close()
		}
		if dr.jumpCleanup != nil {
			dr.jumpCleanup()
		}
		entry.lastUsed = time.Now()
		return entry.client, false, nil
	}

	// Re-check capacity — other goroutines may have inserted while we dialed
	if len(p.sessions) >= maxSessions {
		p.evictOldestLocked()
	}

	now := time.Now()
	p.sessions[key] = &sessionEntry{
		client:      dr.client,
		agentConn:   dr.agentConn,
		jumpCleanup: dr.jumpCleanup,
		key:         key,
		createdAt:   now,
		lastUsed:    now,
	}

	return dr.client, true, nil
}

// remove closes and removes a session by key.
// Returns true if a session was found and removed.
func (p *sessionPool) remove(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	entry, ok := p.sessions[key]
	if !ok {
		return false
	}
	entry.close()
	delete(p.sessions, key)
	return true
}

// reaper periodically removes idle sessions.
func (p *sessionPool) reaper() {
	ticker := time.NewTicker(reaperInterval)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		now := time.Now()
		for key, entry := range p.sessions {
			if now.Sub(entry.lastUsed) > defaultIdleTimeout {
				entry.close()
				delete(p.sessions, key)
			}
		}
		p.mu.Unlock()
	}
}

// GetClient returns a pooled SSH client for the given input, creating a new
// connection if needed. This is the exported entry point for other packages
// (e.g. sftp) to reuse the SSH session pool.
// SSRF check is the caller's responsibility — this function dials by hostname
// since it has no resolved IP context. Callers (sftp, handler) must call
// common.CheckHostSSRF before calling GetClient.
func GetClient(input SSHInput) (*gossh.Client, bool, error) {
	if err := validateInput(&input); err != nil {
		return nil, false, err
	}
	key := sessionKey(input.Host, input.PortInt, input.User)
	return pool.getOrCreate(key, func() (*dialResult, error) {
		// No resolved IP available — dial by hostname.
		// This is acceptable because callers must perform SSRF checks before
		// calling GetClient, and the pool reuses existing connections.
		return dial(input, "", "")
	})
}

// RemoveClient removes a pooled session by connection parameters.
func RemoveClient(host string, port int, user string) bool {
	key := sessionKey(host, port, user)
	return pool.remove(key)
}

// TouchClient updates the lastUsed timestamp for a pooled session.
func TouchClient(host string, port int, user string) {
	key := sessionKey(host, port, user)
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if entry, ok := pool.sessions[key]; ok {
		entry.lastUsed = time.Now()
	}
}

// evictOldestLocked removes the least recently used session.
// Must be called with p.mu held.
func (p *sessionPool) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range p.sessions {
		if oldestKey == "" || entry.lastUsed.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.lastUsed
		}
	}

	if oldestKey != "" {
		if entry, ok := p.sessions[oldestKey]; ok {
			entry.close()
		}
		delete(p.sessions, oldestKey)
	}
}
