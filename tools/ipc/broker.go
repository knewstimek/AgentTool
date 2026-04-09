package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	defaultBrokerPort = 19901

	// brokerMagic identifies this process as an agent-tool broker in status responses.
	// Prevents opBrokerStart from mistaking an unrelated JSON service for a broker (H4).
	brokerMagic = "agent-tool-ipc-broker"

	// maxBrokerReqSize caps incoming JSON request size to prevent OOM via json.Decoder
	// buffer expansion (C1). Covers a 1MB message payload plus JSON envelope overhead.
	maxBrokerReqSize = 1024*1024 + 4096

	// maxMailboxes and maxQueuePerBox prevent unbounded memory growth (H1).
	maxMailboxes   = 1000
	maxQueuePerBox = 10000

	// maxBrokerConns limits concurrent goroutines spawned by serve() (H2).
	maxBrokerConns = 200

	// maxWaitersPerBox limits goroutines blocked on a single mailbox (M1).
	maxWaitersPerBox = 100

	// connDeadlineShort is the deadline for non-wait operations (H3).
	// 30s is generous for post/fetch/status which should complete in milliseconds.
	connDeadlineShort = 30 * time.Second
)

// brokerMsg is a single queued message in a mailbox.
type brokerMsg struct {
	From string    `json:"from"`
	Msg  string    `json:"msg"`
	TS   time.Time `json:"ts"`
}

// brokerReq is a JSON command sent to the broker over TCP (newline-terminated).
type brokerReq struct {
	Op      string `json:"op"`
	To      string `json:"to,omitempty"`
	From    string `json:"from,omitempty"`
	Msg     string `json:"msg,omitempty"`
	Mailbox string `json:"mailbox,omitempty"`
	Timeout int    `json:"timeout,omitempty"`
}

// brokerResp is the broker's JSON reply (newline-terminated).
type brokerResp struct {
	OK        bool           `json:"ok"`
	Error     string         `json:"error,omitempty"`
	Messages  []brokerMsg    `json:"messages,omitempty"`
	Message   *brokerMsg     `json:"message,omitempty"`
	Mailboxes map[string]int `json:"mailboxes,omitempty"`
	Info      string         `json:"info,omitempty"`
}

// brokerState is the in-process broker (only active in the process that won the port).
//
// Lock ordering: owned.Lock > b.mu (never acquire owned while holding b.mu).
type brokerState struct {
	mu      sync.Mutex
	boxes   map[string][]brokerMsg
	waiters map[string][]chan brokerMsg
	ln      net.Listener
	sem     chan struct{} // bounds concurrent handleConn goroutines
	port    int
	stopped bool
}

// owned tracks whether this agent-tool process is the active broker.
var owned struct {
	sync.Mutex
	b *brokerState
}

// opBrokerStart tries to become the broker by binding the port.
// If the port is already taken, verifies it's an agent-tool broker (H4) and connects as client.
func opBrokerStart(input IPCInput) (*Result, IPCOutput, error) {
	port := input.PortInt
	if port <= 0 {
		port = defaultBrokerPort
	}
	bind := input.Bind
	if bind == "" {
		// Default to localhost-only: broker messages may contain sensitive agent data.
		bind = "127.0.0.1"
	}

	owned.Lock()
	defer owned.Unlock()

	if owned.b != nil && !owned.b.stopped {
		return successResult(fmt.Sprintf("Broker already running on port %d (this process)", owned.b.port))
	}

	addr := fmt.Sprintf("%s:%d", bind, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		// Port taken -- verify it's our broker (H4: check brokerMagic)
		resp, cerr := brokerCall(port, brokerReq{Op: "status"})
		if cerr != nil {
			return errorResult("port %d is in use but not responding as a broker: %v\nStop whatever is using port %d first.", port, cerr, port)
		}
		if !resp.OK {
			return errorResult("port %d responded but returned error: %s", port, resp.Error)
		}
		if resp.Info != brokerMagic {
			return errorResult("port %d is in use by an unrelated service (expected agent-tool broker, got info=%q)", port, resp.Info)
		}
		return successResult(fmt.Sprintf("Broker already running on port %d (another process). Ready to use.", port))
	}

	b := &brokerState{
		boxes:   make(map[string][]brokerMsg),
		waiters: make(map[string][]chan brokerMsg),
		ln:      ln,
		sem:     make(chan struct{}, maxBrokerConns),
		port:    port,
	}
	owned.b = b
	go b.serve()

	return successResult(fmt.Sprintf("Broker started on %s. Use post/fetch/wait with port=%d.", addr, port))
}

// opBrokerStop stops the broker if this process owns it.
func opBrokerStop(input IPCInput) (*Result, IPCOutput, error) {
	port := input.PortInt
	if port <= 0 {
		port = defaultBrokerPort
	}

	owned.Lock()
	defer owned.Unlock()

	if owned.b == nil || owned.b.stopped {
		return errorResult("no broker running in this process (port %d)", port)
	}
	if owned.b.port != port {
		return errorResult("broker is on port %d, not %d", owned.b.port, port)
	}

	owned.b.stop()
	owned.b = nil
	return successResult(fmt.Sprintf("Broker stopped (port %d)", port))
}

// serve accepts broker connections until the listener is closed.
// Uses semaphore to bound concurrent goroutines (H2).
func (b *brokerState) serve() {
	for {
		conn, err := b.ln.Accept()
		if err != nil {
			return
		}
		select {
		case b.sem <- struct{}{}:
			go func() {
				defer func() { <-b.sem }()
				b.handleConn(conn)
			}()
		default:
			// At capacity: reject connection immediately
			conn.Close()
		}
	}
}

// stop shuts down the broker and wakes all blocked waiters.
func (b *brokerState) stop() {
	b.ln.Close()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopped = true
	for _, chans := range b.waiters {
		for _, ch := range chans {
			close(ch)
		}
	}
	b.waiters = make(map[string][]chan brokerMsg)
}

// handleConn reads one JSON request, handles it, writes one JSON response.
func (b *brokerState) handleConn(conn net.Conn) {
	defer conn.Close()

	// Short deadline for request parsing; only wait extends it (H3).
	conn.SetDeadline(time.Now().Add(connDeadlineShort))

	var req brokerReq
	// LimitReader prevents OOM via unbounded json.Decoder buffer expansion (C1).
	dec := json.NewDecoder(io.LimitReader(conn, maxBrokerReqSize))
	if err := dec.Decode(&req); err != nil {
		writeJSON(conn, brokerResp{OK: false, Error: "invalid JSON: " + err.Error()})
		return
	}

	// Extend deadline for wait operations to cover the full timeout (H3).
	if req.Op == "wait" && req.Timeout > 0 {
		conn.SetDeadline(time.Now().Add(time.Duration(req.Timeout+10) * time.Second))
	}

	var resp brokerResp
	switch req.Op {
	case "post":
		resp = b.doPost(req)
	case "fetch":
		resp = b.doFetch(req)
	case "wait":
		resp = b.doWait(req)
	case "status":
		resp = b.doStatus()
	default:
		resp = brokerResp{OK: false, Error: fmt.Sprintf("unknown op %q (use: post, fetch, wait, status)", req.Op)}
	}

	writeJSON(conn, resp)
}

func (b *brokerState) doPost(req brokerReq) brokerResp {
	if req.To == "" {
		return brokerResp{OK: false, Error: "to is required"}
	}
	if req.Msg == "" {
		return brokerResp{OK: false, Error: "msg is required"}
	}

	msg := brokerMsg{From: req.From, Msg: req.Msg, TS: time.Now()}

	b.mu.Lock()
	// Deliver directly to a blocked waiter if one exists
	if ws := b.waiters[req.To]; len(ws) > 0 {
		ch := ws[0]
		b.waiters[req.To] = ws[1:]
		b.mu.Unlock()
		ch <- msg // buffered channel (cap 1), never blocks
		return brokerResp{OK: true, Info: "delivered to waiter"}
	}
	// Enforce mailbox and queue limits before enqueueing (H1)
	if _, exists := b.boxes[req.To]; !exists && len(b.boxes) >= maxMailboxes {
		b.mu.Unlock()
		return brokerResp{OK: false, Error: fmt.Sprintf("mailbox limit reached (%d max), cannot create %q", maxMailboxes, req.To)}
	}
	if len(b.boxes[req.To]) >= maxQueuePerBox {
		b.mu.Unlock()
		return brokerResp{OK: false, Error: fmt.Sprintf("mailbox %q is full (%d messages max)", req.To, maxQueuePerBox)}
	}
	b.boxes[req.To] = append(b.boxes[req.To], msg)
	b.mu.Unlock()

	return brokerResp{OK: true, Info: "queued"}
}

func (b *brokerState) doFetch(req brokerReq) brokerResp {
	if req.Mailbox == "" {
		return brokerResp{OK: false, Error: "mailbox is required"}
	}
	b.mu.Lock()
	msgs := b.boxes[req.Mailbox]
	b.boxes[req.Mailbox] = nil
	b.mu.Unlock()

	return brokerResp{OK: true, Messages: msgs}
}

func (b *brokerState) doWait(req brokerReq) brokerResp {
	if req.Mailbox == "" {
		return brokerResp{OK: false, Error: "mailbox is required"}
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 60
	}
	if timeout > 300 {
		timeout = 300
	}

	b.mu.Lock()
	// Return immediately if messages already queued
	if msgs := b.boxes[req.Mailbox]; len(msgs) > 0 {
		msg := msgs[0]
		b.boxes[req.Mailbox] = msgs[1:]
		b.mu.Unlock()
		return brokerResp{OK: true, Message: &msg}
	}
	// Limit waiters per mailbox (M1)
	if len(b.waiters[req.Mailbox]) >= maxWaitersPerBox {
		b.mu.Unlock()
		return brokerResp{OK: false, Error: fmt.Sprintf("too many waiters on mailbox %q (%d max)", req.Mailbox, maxWaitersPerBox)}
	}
	// Register as waiter
	ch := make(chan brokerMsg, 1)
	b.waiters[req.Mailbox] = append(b.waiters[req.Mailbox], ch)
	b.mu.Unlock()

	select {
	case msg, ok := <-ch:
		if !ok {
			return brokerResp{OK: false, Error: "broker stopped while waiting"}
		}
		return brokerResp{OK: true, Message: &msg}

	case <-time.After(time.Duration(timeout) * time.Second):
		// Remove ourselves from waiters. doPost may have concurrently taken ch out of
		// waiters and sent a message just as time.After fired (C2). After cleanup,
		// drain ch non-blocking to handle that race.
		b.mu.Lock()
		ws := b.waiters[req.Mailbox]
		for i, w := range ws {
			if w == ch {
				b.waiters[req.Mailbox] = append(ws[:i], ws[i+1:]...)
				break
			}
		}
		b.mu.Unlock()

		// Non-blocking drain: catch any message delivered between time.After firing
		// and our waiter cleanup (C2 fix).
		select {
		case msg, ok := <-ch:
			if ok {
				return brokerResp{OK: true, Message: &msg}
			}
			return brokerResp{OK: false, Error: "broker stopped while waiting"}
		default:
		}

		return brokerResp{OK: false, Error: fmt.Sprintf("wait timed out after %ds -- no message in mailbox %q", timeout, req.Mailbox)}
	}
}

func (b *brokerState) doStatus() brokerResp {
	b.mu.Lock()
	defer b.mu.Unlock()
	sizes := make(map[string]int)
	for k, msgs := range b.boxes {
		if len(msgs) > 0 {
			sizes[k] = len(msgs)
		}
	}
	for k, ws := range b.waiters {
		if len(ws) > 0 {
			if _, ok := sizes[k]; !ok {
				sizes[k] = 0
			}
		}
	}
	// Include brokerMagic so opBrokerStart can distinguish us from unrelated services (H4).
	return brokerResp{OK: true, Mailboxes: sizes, Info: brokerMagic}
}

// writeJSON marshals v and writes it as a newline-terminated JSON line.
// Write errors are logged but not propagated: the connection will be closed by
// handleConn's defer, so resource cleanup is guaranteed regardless (M3).
func writeJSON(conn net.Conn, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Printf("ipc broker: writeJSON marshal error: %v", err)
		return
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		log.Printf("ipc broker: writeJSON write error: %v", err)
	}
}

// brokerCall connects to the broker, sends one request, reads one response.
func brokerCall(port int, req brokerReq) (brokerResp, error) {
	callTimeout := 10 * time.Second
	if req.Op == "wait" && req.Timeout > 0 {
		callTimeout = time.Duration(req.Timeout+15) * time.Second
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		return brokerResp{}, fmt.Errorf("connect to broker on port %d: %w", port, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(callTimeout))

	data, _ := json.Marshal(req)
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return brokerResp{}, fmt.Errorf("send to broker: %w", err)
	}

	// Use a larger scanner buffer since fetch may return many messages (M4).
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return brokerResp{}, fmt.Errorf("read broker response: %w", err)
		}
		return brokerResp{}, fmt.Errorf("broker closed connection without response")
	}
	var resp brokerResp
	if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
		return brokerResp{}, fmt.Errorf("invalid broker response: %w", err)
	}
	return resp, nil
}

func brokerPortFrom(input IPCInput) int {
	if input.PortInt > 0 {
		return input.PortInt
	}
	return defaultBrokerPort
}

// opPost sends a message to a named mailbox via the broker.
func opPost(_ context.Context, input IPCInput) (*Result, IPCOutput, error) {
	if input.To == "" {
		return errorResult("to is required (target mailbox name, e.g. \"agentB\")")
	}
	if input.Message == "" {
		return errorResult("message is required")
	}
	port := brokerPortFrom(input)
	resp, err := brokerCall(port, brokerReq{Op: "post", To: input.To, From: input.From, Msg: input.Message})
	if err != nil {
		return errorResult("cannot reach broker on port %d: %v\nStart broker first: operation=broker_start", port, err)
	}
	if !resp.OK {
		return errorResult("post failed: %s", resp.Error)
	}
	info := resp.Info
	if info == "" {
		info = "queued"
	}
	return successResult(fmt.Sprintf("Posted to mailbox %q (%s, port %d)", input.To, info, port))
}

// opFetch retrieves all pending messages from a mailbox without blocking.
func opFetch(_ context.Context, input IPCInput) (*Result, IPCOutput, error) {
	if input.Mailbox == "" {
		return errorResult("mailbox is required (your mailbox name, e.g. \"agentA\")")
	}
	port := brokerPortFrom(input)
	resp, err := brokerCall(port, brokerReq{Op: "fetch", Mailbox: input.Mailbox})
	if err != nil {
		return errorResult("cannot reach broker on port %d: %v\nStart broker first: operation=broker_start", port, err)
	}
	if !resp.OK {
		return errorResult("fetch failed: %s", resp.Error)
	}
	if len(resp.Messages) == 0 {
		return successResult(fmt.Sprintf("No messages in mailbox %q", input.Mailbox))
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d message(s) in mailbox %q:\n", len(resp.Messages), input.Mailbox)
	for i, m := range resp.Messages {
		fmt.Fprintf(&sb, "\n[%d] from=%q ts=%s\n%s", i+1, m.From, m.TS.Format(time.RFC3339), m.Msg)
	}
	return successResult(sb.String())
}

// opWait blocks until a message arrives in the mailbox or timeout expires.
// No tokens are consumed while waiting.
func opWait(_ context.Context, input IPCInput) (*Result, IPCOutput, error) {
	if input.Mailbox == "" {
		return errorResult("mailbox is required (your mailbox name, e.g. \"agentA\")")
	}
	timeout := input.TimeoutInt
	if timeout <= 0 {
		timeout = 60
	}
	if timeout > 300 {
		timeout = 300
	}
	port := brokerPortFrom(input)
	resp, err := brokerCall(port, brokerReq{Op: "wait", Mailbox: input.Mailbox, Timeout: timeout})
	if err != nil {
		return errorResult("cannot reach broker on port %d: %v\nStart broker first: operation=broker_start", port, err)
	}
	if !resp.OK {
		return errorResult("%s", resp.Error)
	}
	m := resp.Message
	return successResult(fmt.Sprintf("Message in mailbox %q from=%q ts=%s:\n%s", input.Mailbox, m.From, m.TS.Format(time.RFC3339), m.Msg))
}

// opBrokerStatus shows queued message counts per mailbox.
func opBrokerStatus(input IPCInput) (*Result, IPCOutput, error) {
	port := brokerPortFrom(input)
	resp, err := brokerCall(port, brokerReq{Op: "status"})
	if err != nil {
		return errorResult("broker not reachable on port %d: %v", port, err)
	}
	if !resp.OK {
		return errorResult("status failed: %s", resp.Error)
	}
	if len(resp.Mailboxes) == 0 {
		return successResult(fmt.Sprintf("Broker on port %d: no active mailboxes", port))
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Broker on port %d:\n", port)
	for name, count := range resp.Mailboxes {
		fmt.Fprintf(&sb, "  %s: %d queued\n", name, count)
	}
	return successResult(sb.String())
}
