package ipc

import (
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	poolIdleTimeout = 5 * time.Minute
	poolMaxConns    = 10
	sweepInterval   = 1 * time.Minute
)

type poolConn struct {
	conn      net.Conn
	key       string
	createdAt time.Time
	lastUsed  time.Time
	listener  net.Listener
}

var pool = struct {
	sync.Mutex
	conns map[string]*poolConn
}{
	conns: make(map[string]*poolConn),
}

func init() {
	// Background sweeper for idle connections (#6)
	go func() {
		for range time.Tick(sweepInterval) {
			sweepIdle()
		}
	}()
}

// sweepIdle removes connections that have exceeded idle timeout.
func sweepIdle() {
	pool.Lock()
	defer pool.Unlock()

	now := time.Now()
	for key, pc := range pool.conns {
		if now.Sub(pc.lastUsed) > poolIdleTimeout {
			pc.conn.Close()
			if pc.listener != nil {
				pc.listener.Close()
			}
			delete(pool.conns, key)
		}
	}
}

// checkoutConn removes and returns a connection from the pool.
// Caller owns the connection: must putConn back or Close it.
// Eliminates TOCTOU between get/remove (#5) and
// avoids isConnAlive data consumption (#1).
func checkoutConn(key string) *poolConn {
	pool.Lock()
	defer pool.Unlock()

	pc, ok := pool.conns[key]
	if !ok {
		return nil
	}
	delete(pool.conns, key)

	// Check idle timeout
	if time.Since(pc.lastUsed) > poolIdleTimeout {
		pc.conn.Close()
		if pc.listener != nil {
			pc.listener.Close()
		}
		return nil
	}

	return pc
}

// putConn stores a connection in the pool.
// Closes any existing connection with the same key (#3).
// If pool is full, evicts the oldest idle connection.
func putConn(key string, conn net.Conn, listener net.Listener) {
	// Clear deadlines before pooling (#8)
	conn.SetReadDeadline(time.Time{})
	conn.SetWriteDeadline(time.Time{})

	pool.Lock()
	defer pool.Unlock()

	// Close existing connection with same key (#3)
	if old, ok := pool.conns[key]; ok {
		old.conn.Close()
		if old.listener != nil {
			old.listener.Close()
		}
		delete(pool.conns, key)
	}

	// Evict oldest if pool is full
	if len(pool.conns) >= poolMaxConns {
		var oldestKey string
		var oldestTime time.Time
		for k, pc := range pool.conns {
			if oldestKey == "" || pc.lastUsed.Before(oldestTime) {
				oldestKey = k
				oldestTime = pc.lastUsed
			}
		}
		if oldestKey != "" {
			old := pool.conns[oldestKey]
			old.conn.Close()
			if old.listener != nil {
				old.listener.Close()
			}
			delete(pool.conns, oldestKey)
		}
	}

	now := time.Now()
	pool.conns[key] = &poolConn{
		conn:      conn,
		key:       key,
		createdAt: now,
		lastUsed:  now,
		listener:  listener,
	}
}

// removeConn removes and closes a connection from the pool.
func removeConn(key string) {
	pool.Lock()
	defer pool.Unlock()

	if pc, ok := pool.conns[key]; ok {
		pc.conn.Close()
		if pc.listener != nil {
			pc.listener.Close()
		}
		delete(pool.conns, key)
	}
}

func recvPoolKey(port int) string {
	return fmt.Sprintf("recv:%d", port)
}

func sendPoolKey(host string) string {
	return fmt.Sprintf("send:%s", host)
}
