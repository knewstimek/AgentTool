package debug

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sync"
	"time"

	"github.com/google/go-dap"
)

// listenAddrRe matches host:port patterns in adapter stdout lines.
// Examples: "127.0.0.1:12345", "localhost:5678", "[::1]:9090"
var listenAddrRe = regexp.MustCompile(`((?:\d{1,3}\.){3}\d{1,3}|localhost|\[::1?\]):\d{2,5}`)

// extractListenAddress scans a line of adapter stdout for a host:port address.
func extractListenAddress(line string) string {
	return listenAddrRe.FindString(line)
}

const (
	debugIdleTimeout = 30 * time.Minute
	debugMaxSessions = 5
	debugReaperInterval = 60 * time.Second
)

// debugSession represents a single DAP debug session with an adapter.
type debugSession struct {
	id        string
	mode      string // "stdio" or "tcp"
	launchMode bool   // true if created via launch (should terminate debuggee on disconnect)
	client    *dapClient

	// stdio mode: adapter process
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser

	// tcp mode: underlying connection (closed on session cleanup)
	conn net.Conn

	// Session state
	mu              sync.Mutex
	state           string // "initializing", "running", "stopped", "exited", "terminated"
	configDone      bool   // true after configurationDone has been sent
	lastStoppedTID  int    // thread ID from the most recent StoppedEvent (for default threadId in continue/step)

	// Event handling
	events        *eventBuffer
	stoppedCh     chan dap.Message // signaled when a stopped event arrives
	initializedCh chan struct{}    // closed when the adapter sends initialized event
	done          chan struct{}    // closed to stop the event loop

	// Adapter capabilities (populated after initialize)
	capabilities dap.Capabilities

	createdAt time.Time
	lastUsed  time.Time
}

// close terminates the debug session, stopping the event loop and
// killing the adapter process if in stdio mode.
func (s *debugSession) close() {
	// Signal event loop to stop
	select {
	case <-s.done:
		// Already closed
	default:
		close(s.done)
	}

	// Close the DAP connection
	if s.conn != nil {
		s.conn.Close()
	}
	if s.stdin != nil {
		s.stdin.Close()
	}
	if s.stdout != nil {
		s.stdout.Close()
	}

	// Kill the adapter process (stdio mode)
	if s.cmd != nil && s.cmd.Process != nil {
		if runtime.GOOS == "windows" {
			// Tree kill on Windows to avoid orphaned child processes
			killCmd := exec.Command("taskkill", "/PID",
				fmt.Sprintf("%d", s.cmd.Process.Pid), "/T", "/F")
			killCmd.Run()
		} else {
			// Graceful shutdown: SIGTERM first, then SIGKILL after timeout
			s.cmd.Process.Signal(os.Interrupt)
			termDone := make(chan struct{})
			go func() {
				s.cmd.Wait()
				close(termDone)
			}()
			select {
			case <-termDone:
				return // Graceful exit
			case <-time.After(3 * time.Second):
				s.cmd.Process.Kill()
			}
		}
		// Wait briefly to reap the process (Windows path, or after SIGKILL)
		waitDone := make(chan struct{})
		go func() {
			s.cmd.Wait()
			close(waitDone)
		}()
		select {
		case <-waitDone:
		case <-time.After(5 * time.Second):
			s.cmd.Process.Kill()
		}
	}
}

// getState returns the current session state.
func (s *debugSession) getState() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// pushEvent adds an informational event to the session's event buffer.
// Used for diagnostics (e.g., handshake signing method).
func (s *debugSession) pushEvent(msg string) {
	s.events.push(dapEvent{
		Type:      "agent-tool",
		Body:      msg,
		Timestamp: time.Now(),
	})
}

// sessionPool manages active debug sessions.
type sessionPool struct {
	mu       sync.Mutex
	sessions map[string]*debugSession
}

var pool = &sessionPool{
	sessions: make(map[string]*debugSession),
}

func init() {
	go pool.reaper()
}

// get returns an existing session by ID.
// lastUsed is protected by the pool mutex (all reads/writes happen under p.mu).
func (p *sessionPool) get(id string) (*debugSession, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.sessions[id]
	if ok {
		s.lastUsed = time.Now()
	}
	return s, ok
}

// add registers a new session. Returns error if at capacity.
func (p *sessionPool) add(s *debugSession) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.sessions[s.id]; exists {
		return fmt.Errorf("session %q already exists", s.id)
	}
	if len(p.sessions) >= debugMaxSessions {
		p.evictOldestLocked()
	}
	p.sessions[s.id] = s
	return nil
}

// remove closes and removes a session by ID.
func (p *sessionPool) remove(id string) bool {
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
func (p *sessionPool) reaper() {
	ticker := time.NewTicker(debugReaperInterval)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		now := time.Now()
		for id, s := range p.sessions {
			if now.Sub(s.lastUsed) > debugIdleTimeout {
				s.close()
				delete(p.sessions, id)
			}
		}
		p.mu.Unlock()
	}
}

// evictOldestLocked removes the least recently used session.
// Must be called with p.mu held.
func (p *sessionPool) evictOldestLocked() {
	var oldestID string
	var oldestTime time.Time
	for id, s := range p.sessions {
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

// listSessions returns a summary of all active sessions.
func (p *sessionPool) listSessions() []sessionInfo {
	p.mu.Lock()
	defer p.mu.Unlock()

	result := make([]sessionInfo, 0, len(p.sessions))
	for _, s := range p.sessions {
		result = append(result, sessionInfo{
			ID:        s.id,
			Mode:      s.mode,
			State:     s.getState(),
			CreatedAt: s.createdAt,
			LastUsed:  s.lastUsed,
		})
	}
	return result
}

// sessionInfo holds summary data returned by listSessions.
type sessionInfo struct {
	ID        string
	Mode      string
	State     string
	CreatedAt time.Time
	LastUsed  time.Time
}

// createStdioSession starts a debug adapter as a child process.
//
// Two communication patterns are supported:
//  1. TCP mode (dlv, debugpy): adapter prints a TCP listen address to stdout.
//     We detect the address and connect via TCP.
//  2. Stdio mode (lldb-dap, codelldb): adapter speaks DAP directly on stdin/stdout.
//     We detect this by seeing a "Content-Length:" header (DAP framing).
//
// A relay goroutine reads the real stdout, checking for both patterns.
// Data is forwarded through an io.Pipe so the DAP client can read it
// in stdio mode without losing bytes consumed during detection.
func createStdioSession(id, command string, args []string, cwd string) (*debugSession, error) {
	cmd := exec.Command(command, args...)
	cmd.Stderr = os.Stderr
	if cwd != "" {
		cmd.Dir = cwd
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		stdinPipe.Close()
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		stdinPipe.Close()
		stdoutPipe.Close()
		return nil, fmt.Errorf("failed to start debug adapter %q: %w", command, err)
	}

	// Relay goroutine: reads real stdout, checks for TCP address or DAP content,
	// and forwards all bytes to the pipe for potential stdio mode.
	pr, pw := io.Pipe()
	addrCh := make(chan string, 1)       // TCP address detected
	stdioDetected := make(chan struct{}) // DAP Content-Length seen

	go func() {
		defer pw.Close()
		buf := make([]byte, 4096)
		var accum []byte
		signaled := false
		// Cap accum buffer at 1MB to prevent unbounded memory growth
		// if adapter sends lots of output before we detect the mode
		const maxAccum = 1 << 20

		for {
			n, readErr := stdoutPipe.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				if len(accum) < maxAccum {
					remain := maxAccum - len(accum)
					if len(chunk) > remain {
						accum = append(accum, chunk[:remain]...)
					} else {
						accum = append(accum, chunk...)
					}
				}

				if !signaled {
					// Check for TCP listen address (e.g. "127.0.0.1:12345")
					if addr := extractListenAddress(string(accum)); addr != "" {
						addrCh <- addr
						signaled = true
						// Drain remaining stdout so adapter doesn't block on write
						io.Copy(io.Discard, stdoutPipe)
						return
					}

					// Check for DAP framing header — means adapter uses stdio mode
					if bytes.Contains(accum, []byte("Content-Length:")) {
						signaled = true
						select {
						case stdioDetected <- struct{}{}:
						default:
						}
					}
				}

				// Relay to pipe (for stdio mode DAP client)
				if _, writeErr := pw.Write(chunk); writeErr != nil {
					return
				}
			}

			if readErr != nil {
				if !signaled {
					addrCh <- "" // EOF without finding anything
				}
				return
			}
		}
	}()

	now := time.Now()

	select {
	case addr := <-addrCh:
		// Close stdio resources — not needed for TCP mode
		pr.Close()
		stdinPipe.Close()

		if addr != "" {
			// TCP mode: adapter started a TCP server — connect to it.
			// No SSRF check: adapter was spawned locally by us, and the debug
			// tool already allows arbitrary command execution via adapter_command.
			// See createTCPSession comment for rationale.
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				cmd.Process.Kill()
				return nil, fmt.Errorf("adapter listening on %s but connection failed: %w", addr, err)
			}

			s := &debugSession{
				id:            id,
				mode:          "stdio",
				client:        newDAPClient(conn, conn),
				cmd:           cmd,
				conn:          conn,
				state:         "initializing",
				events:        newEventBuffer(),
				stoppedCh:     make(chan dap.Message, 1),
				initializedCh: make(chan struct{}),
				done:          make(chan struct{}),
				createdAt:     now,
				lastUsed:      now,
			}
			go s.eventLoop()
			return s, nil
		}

		// Empty address — adapter exited immediately without DAP output
		cmd.Process.Kill()
		return nil, fmt.Errorf("debug adapter exited without producing a listen address or DAP data")

	case <-stdioDetected:
		// Stdio mode: adapter speaks DAP directly on stdin/stdout.
		// Read from the pipe relay (which already buffered early data),
		// write to the adapter's stdin pipe.
		s := &debugSession{
			id:            id,
			mode:          "stdio",
			client:        newDAPClient(pr, stdinPipe),
			cmd:           cmd,
			stdin:         stdinPipe,
			stdout:        stdoutPipe,
			state:         "initializing",
			events:        newEventBuffer(),
			stoppedCh:     make(chan dap.Message, 1),
			initializedCh: make(chan struct{}),
			done:          make(chan struct{}),
			createdAt:     now,
			lastUsed:      now,
		}
		go s.eventLoop()
		return s, nil

	case <-time.After(5 * time.Second):
		// Timeout: no TCP address, no DAP content. Adapter is likely a pure
		// stdio adapter waiting for input. Assume stdio mode.
		s := &debugSession{
			id:            id,
			mode:          "stdio",
			client:        newDAPClient(pr, stdinPipe),
			cmd:           cmd,
			stdin:         stdinPipe,
			stdout:        stdoutPipe,
			state:         "initializing",
			events:        newEventBuffer(),
			stoppedCh:     make(chan dap.Message, 1),
			initializedCh: make(chan struct{}),
			done:          make(chan struct{}),
			createdAt:     now,
			lastUsed:      now,
		}
		go s.eventLoop()
		return s, nil
	}
}

// createTCPSession connects to a running debug adapter over TCP.
//
// No SSRF check: the debug tool already allows arbitrary command execution
// via adapter_command, so restricting TCP targets provides no meaningful
// security boundary. The tool is excluded from safePermissionEntries
// (requires manual user approval for every invocation).
func createTCPSession(id, address string) (*debugSession, error) {
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to debug adapter at %s: %w", address, err)
	}

	now := time.Now()
	s := &debugSession{
		id:            id,
		mode:          "tcp",
		client:        newDAPClient(conn, conn),
		conn:          conn,
		state:         "initializing",
		events:        newEventBuffer(),
		stoppedCh:     make(chan dap.Message, 1),
		initializedCh: make(chan struct{}),
		done:          make(chan struct{}),
		createdAt:     now,
		lastUsed:      now,
	}

	// Start event loop
	go s.eventLoop()

	return s, nil
}
