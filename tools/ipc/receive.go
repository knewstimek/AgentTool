package ipc

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// opReceive listens on a TCP port and blocks until a MESSAGE arrives or timeout.
// Reuses existing connections from the pool (checkout pattern).
// Responds to PING with PONG automatically.
func opReceive(ctx context.Context, input IPCInput) (*Result, IPCOutput, error) {
	port := input.PortInt
	if port <= 0 || port > 65535 {
		return errorResult("port must be between 1 and 65535")
	}

	timeout := input.TimeoutInt
	if timeout <= 0 {
		timeout = 60
	}
	if timeout > 300 {
		timeout = 300
	}

	// Default to localhost for security (#7)
	bind := input.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}

	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	key := recvPoolKey(port)

	// Try to reuse pooled connection (checkout: removed from pool)
	pc := checkoutConn(key)
	if pc != nil {
		return recvFromConn(ctx, pc.conn, pc.conn.RemoteAddr().String(), deadline, key)
	}

	// No pooled connection, listen for new one
	addr := fmt.Sprintf("%s:%d", bind, port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return errorResult("failed to listen on %s: %v", addr, err)
	}

	// Cancel listener on context cancellation (#2: use done channel to prevent goroutine leak)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-done:
			// normal path, exit goroutine immediately
		}
	}()

	listener.(*net.TCPListener).SetDeadline(deadline)
	conn, err := listener.Accept()

	// Close listener and stop goroutine
	listener.Close()
	close(done)

	if err != nil {
		if ctx.Err() != nil {
			return errorResult("receive cancelled")
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return errorResult("receive timed out after %ds -- no connection on port %d", timeout, port)
		}
		return errorResult("accept failed: %v", err)
	}

	remoteAddr := conn.RemoteAddr().String()
	return recvFromConn(ctx, conn, remoteAddr, deadline, key)
}

// recvFromConn reads packets from a connection until MESSAGE or timeout.
// On success, stores connection back in pool for reuse.
// On failure, closes the connection (already checked out of pool).
func recvFromConn(ctx context.Context, conn net.Conn, remoteAddr string, deadline time.Time, poolKey string) (*Result, IPCOutput, error) {
	const maxNonMessage = 100
	nonMessageCount := 0

	conn.SetReadDeadline(deadline)
	for {
		// Check context cancellation
		select {
		case <-ctx.Done():
			conn.Close()
			return errorResult("receive cancelled")
		default:
		}

		typ, payload, err := readPacket(conn)
		if err != nil {
			conn.Close()
			if ctx.Err() != nil {
				return errorResult("receive cancelled")
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return errorResult("receive timed out -- connected from %s but no message", remoteAddr)
			}
			return errorResult("read error from %s: %v", remoteAddr, err)
		}

		switch typ {
		case TypePing:
			if err := writePacket(conn, TypePong, nil); err != nil {
				conn.Close()
				return errorResult("failed to send PONG to %s: %v", remoteAddr, err)
			}
			nonMessageCount++
		case TypeMessage:
			// Return connection to pool for reuse
			putConn(poolKey, conn, nil)

			msg := string(payload)
			text := fmt.Sprintf("Message from %s:\n%s", remoteAddr, msg)
			return &Result{
				Content: []mcp.Content{&mcp.TextContent{Text: text}},
			}, IPCOutput{Message: msg, Remote: remoteAddr}, nil
		default:
			nonMessageCount++
		}

		if nonMessageCount > maxNonMessage {
			conn.Close()
			return errorResult("too many non-message packets from %s, closing", remoteAddr)
		}
	}
}
