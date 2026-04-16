package ipc

import (
	"context"
	"fmt"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type IPCInput struct {
	// Resolved int values set by Handle after FlexInt conversion.
	PortInt    int `json:"-"`
	TimeoutInt int `json:"-"`

	Operation string      `json:"operation" jsonschema:"Operation: send, receive, ping, broker_start, broker_stop, post, fetch, wait, broker_status,required"`
	Host      string      `json:"host,omitempty" jsonschema:"Remote host:port (e.g. '192.168.1.5:19900'). For send/ping"`
	Port      interface{} `json:"port,omitempty" jsonschema:"Port number. receive default: 19900, broker default: 19901"`
	Message   string      `json:"message,omitempty" jsonschema:"Message text. For send, post"`
	Timeout   interface{} `json:"timeout,omitempty" jsonschema:"Timeout in seconds. receive/wait default: 60 (max 300), send/ping default: 10"`
	Bind      string      `json:"bind,omitempty" jsonschema:"Bind address. Default: 127.0.0.1 (local only). Use 0.0.0.0 for all interfaces"`

	// Broker fields
	To      string `json:"to,omitempty" jsonschema:"Target mailbox name. For post (e.g. 'agentB')"`
	From    string `json:"from,omitempty" jsonschema:"Sender name. For post (e.g. 'agentA')"`
	Mailbox string `json:"mailbox,omitempty" jsonschema:"Your mailbox name. For fetch/wait (e.g. 'agentA')"`
}

type IPCOutput struct {
	Message string `json:"message"`
	Remote  string `json:"remote,omitempty"`
}

type Result = mcp.CallToolResult

func Handle(ctx context.Context, req *mcp.CallToolRequest, input IPCInput) (*Result, IPCOutput, error) {
	port, ok := common.FlexInt(input.Port)
	if !ok {
		return errorResult("port must be an integer")
	}
	timeout, ok := common.FlexInt(input.Timeout)
	if !ok {
		return errorResult("timeout must be an integer")
	}
	input.PortInt = port
	input.TimeoutInt = timeout

	switch input.Operation {
	case "send":
		return opSend(ctx, input)
	case "receive":
		if input.PortInt <= 0 {
			input.PortInt = 19900
		}
		return opReceive(ctx, input)
	case "ping":
		return opPing(ctx, input)
	case "broker_start":
		return opBrokerStart(input)
	case "broker_stop":
		return opBrokerStop(input)
	case "post":
		return opPost(ctx, input)
	case "fetch":
		return opFetch(ctx, input)
	case "wait":
		return opWait(ctx, input)
	case "broker_status":
		return opBrokerStatus(input)
	default:
		return errorResult("invalid operation %q (use: send, receive, ping, broker_start, broker_stop, post, fetch, wait, broker_status)", input.Operation)
	}
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "ipc",
		Description: `Inter-process communication between AI agent sessions over TCP.

Operations:

Point-to-point (no broker needed):
  send: Connect to remote host and send a text message.
  receive: Listen on a port and block until a message arrives (or timeout).
    Auto-responds to PING with PONG. No tokens consumed while waiting.
  ping: Send PING to remote host, wait for PONG, measure RTT.

Broker-based (reliable, no missed messages):
  broker_start: Start a message broker on this process (default port 19901).
    If another process already owns the port, connects as client instead.
    First caller wins the broker role. Both sessions use the same broker.
  broker_stop: Stop the broker (only if this process owns it).
  post: Send a message to a named mailbox (non-blocking).
    Params: to (target mailbox), from (your name), message, port (broker port).
  fetch: Get all pending messages from your mailbox (non-blocking, returns immediately).
    Params: mailbox (your name), port.
  wait: Block until a message arrives in your mailbox (or timeout).
    Params: mailbox, timeout (default 60s, max 300s), port.
    No tokens consumed while waiting.
  broker_status: Show queued message counts per mailbox.

Broker workflow (two sessions, no missed messages):
  Session A: broker_start -> wait(mailbox="A") [blocks until B posts]
  Session B: broker_start -> post(to="A", from="B", message="hello") -> wait(mailbox="B")
  Session A: receives "hello", replies: post(to="B", from="A", message="...") -> wait(mailbox="A")
  [repeat]

Point-to-point flow:
  Session A: receive(port=19900, timeout=120) -- blocks waiting
  Session B: send(host="localhost:19900", message="...")
  Session A gets the message, then: send(host="<B's address>:19900", message="response...")
  Session B: receive(port=19900, timeout=120)

Same machine: host="localhost:19900". Max message size: 1MB. Max timeout: 300s.

Persistent worker pattern (loop until shutdown):
  broker_start -> loop { wait(mailbox="me") -> [process task] -> post(to="orchestrator", ...) }
  To stop: orchestrator posts message="shutdown", worker checks and exits loop.`,
	}, Handle)
}

func successResult(msg string) (*Result, IPCOutput, error) {
	return &Result{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, IPCOutput{Message: msg}, nil
}

func errorResult(format string, args ...any) (*Result, IPCOutput, error) {
	msg := fmt.Sprintf(format, args...)
	return &Result{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, IPCOutput{}, nil
}
