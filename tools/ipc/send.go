package ipc

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// opSend connects to a remote host and sends a MESSAGE.
// Reuses existing pooled connection if available (checkout pattern).
func opSend(ctx context.Context, input IPCInput) (*Result, IPCOutput, error) {
	if input.Host == "" {
		return errorResult("host is required (e.g. \"192.168.1.5:19900\" or \"localhost:19900\")")
	}
	if input.Message == "" {
		return errorResult("message is required")
	}

	timeout := input.TimeoutInt
	if timeout <= 0 {
		timeout = 10
	}
	if timeout > 300 {
		timeout = 300
	}

	key := sendPoolKey(input.Host)

	// Try pooled connection first (checkout: removed from pool)
	pc := checkoutConn(key)
	if pc != nil {
		pc.conn.SetWriteDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
		if err := writePacket(pc.conn, TypeMessage, []byte(input.Message)); err == nil {
			// Success: return connection to pool
			putConn(key, pc.conn, nil)
			msg := fmt.Sprintf("Message sent to %s (%d bytes, reused connection)", input.Host, len(input.Message))
			return &Result{
				Content: []mcp.Content{&mcp.TextContent{Text: msg}},
			}, IPCOutput{Message: msg, Remote: input.Host}, nil
		}
		// Write failed: connection dead, close and fall through to new connection
		pc.conn.Close()
	}

	// New connection
	dialer := net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", input.Host)
	if err != nil {
		return errorResult("failed to connect to %s: %v", input.Host, err)
	}

	conn.SetWriteDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	if err := writePacket(conn, TypeMessage, []byte(input.Message)); err != nil {
		conn.Close()
		return errorResult("failed to send message to %s: %v", input.Host, err)
	}

	// Store in pool for reuse
	putConn(key, conn, nil)

	msg := fmt.Sprintf("Message sent to %s (%d bytes)", input.Host, len(input.Message))
	return &Result{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, IPCOutput{Message: msg, Remote: input.Host}, nil
}

// opPing connects to a remote host and sends PING, waits for PONG.
func opPing(ctx context.Context, input IPCInput) (*Result, IPCOutput, error) {
	if input.Host == "" {
		return errorResult("host is required (e.g. \"192.168.1.5:19900\" or \"localhost:19900\")")
	}

	timeout := input.TimeoutInt
	if timeout <= 0 {
		timeout = 5
	}
	if timeout > 300 {
		timeout = 300
	}

	dialer := net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", input.Host)
	if err != nil {
		return errorResult("failed to connect to %s: %v", input.Host, err)
	}
	defer conn.Close()

	start := time.Now()
	if err := sendPing(conn, time.Duration(timeout)*time.Second); err != nil {
		return errorResult("ping %s failed: %v", input.Host, err)
	}
	rtt := time.Since(start)

	msg := fmt.Sprintf("PONG from %s (rtt=%s)", input.Host, rtt.Round(time.Microsecond))
	return &Result{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, IPCOutput{Message: msg, Remote: input.Host}, nil
}
