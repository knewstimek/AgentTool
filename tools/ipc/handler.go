package ipc

import (
	"context"
	"fmt"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type IPCInput struct {
	Operation string `json:"operation" jsonschema:"Operation: send, receive, ping,required"`
	Host      string `json:"host,omitempty" jsonschema:"Remote host:port (e.g. '192.168.1.5:19900'). For send/ping"`
	Port      int    `json:"port,omitempty" jsonschema:"Port to listen on. For receive. Default: 19900"`
	Message   string `json:"message,omitempty" jsonschema:"Message text to send. For send"`
	Timeout   int    `json:"timeout,omitempty" jsonschema:"Timeout in seconds. receive default: 60 (max 300), send/ping default: 10"`
	Bind      string `json:"bind,omitempty" jsonschema:"Bind address for receive. Default: 0.0.0.0 (all interfaces). Use 127.0.0.1 for local only"`
}

type IPCOutput struct {
	Message string `json:"message"`
	Remote  string `json:"remote,omitempty"`
}

type Result = mcp.CallToolResult

func Handle(ctx context.Context, req *mcp.CallToolRequest, input IPCInput) (*Result, IPCOutput, error) {
	switch input.Operation {
	case "send":
		return opSend(ctx, input)
	case "receive":
		if input.Port <= 0 {
			input.Port = 19900
		}
		return opReceive(ctx, input)
	case "ping":
		return opPing(ctx, input)
	default:
		return errorResult("invalid operation %q (use: send, receive, ping)", input.Operation)
	}
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "ipc",
		Description: `Inter-process communication between AI agent sessions over TCP.
Use when the user wants to share information, coordinate, or collaborate with another AI agent session
(e.g. "ask the other session about X", "send this to the game server session", "wait for a message").
Each call handles one message. For back-and-forth, alternate send and receive.

Operations:
  send: Connect to remote host and send a text message.
  receive: Listen on a port and block until a message arrives (or timeout).
    Auto-responds to PING with PONG. No tokens consumed while waiting.
  ping: Send PING to remote host, wait for PONG, measure RTT.

Conversation flow:
  Session A: receive(port=19900, timeout=120)  -- blocks waiting
  Session B: send(host="<A's address>:19900", message="question or data...")
  Session A gets the message, processes it, then:
  Session A: send(host="<B's address>:19900", message="response...")
  Session B: receive(port=19900, timeout=120)  -- gets the response

Same machine: host="localhost:19900". Different machines: use IP address.
For local-only, set bind="127.0.0.1" on receive.
Max message size: 1MB. Max timeout: 300s.`,
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
