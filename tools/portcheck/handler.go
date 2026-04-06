package portcheck

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultTimeoutSec = 5
	maxTimeoutSec     = 30
)

type PortCheckInput struct {
	Host       string      `json:"host" jsonschema:"Hostname or IP address to check,required"`
	Port       interface{} `json:"port" jsonschema:"Port number to check (1-65535),required"`
	TimeoutSec interface{} `json:"timeout_sec,omitempty" jsonschema:"Connection timeout in seconds. Default: 5, Max: 30"`
}

type PortCheckOutput struct {
	Result string `json:"result"`
	Open   bool   `json:"open"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input PortCheckInput) (*mcp.CallToolResult, PortCheckOutput, error) {
	if strings.TrimSpace(input.Host) == "" {
		return errorResult("host is required")
	}
	port, ok := common.FlexInt(input.Port)
	if !ok {
		return errorResult("port must be an integer")
	}
	if port < 1 || port > 65535 {
		return errorResult(fmt.Sprintf("invalid port: %d (must be 1-65535)", port))
	}

	timeoutSec, ok := common.FlexInt(input.TimeoutSec)
	if !ok {
		return errorResult("timeout_sec must be an integer")
	}
	if timeoutSec <= 0 {
		timeoutSec = defaultTimeoutSec
	}
	if timeoutSec > maxTimeoutSec {
		return errorResult(fmt.Sprintf("timeout_sec exceeds maximum (%d)", maxTimeoutSec))
	}

	// No SSRF protection — port check is a diagnostic tool where users explicitly
	// specify the host. Checking local/internal services is a legitimate use case.
	// Use JoinHostPort for correct IPv6 bracket handling
	addr := net.JoinHostPort(input.Host, strconv.Itoa(port))
	timeout := time.Duration(timeoutSec) * time.Second

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	elapsed := time.Since(start)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Port check: %s\n", addr))

	if err != nil {
		sb.WriteString("Status: CLOSED\n")

		// Categorize the error for clearer diagnostics
		errStr := err.Error()
		switch {
		case strings.Contains(errStr, "refused"):
			sb.WriteString("Error: connection refused\n")
		case strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline"):
			sb.WriteString("Error: connection timed out\n")
		case strings.Contains(errStr, "no such host") || strings.Contains(errStr, "lookup"):
			sb.WriteString("Error: DNS resolution failed\n")
		default:
			sb.WriteString("Error: connection failed\n")
		}

		result := sb.String()
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: result}},
		}, PortCheckOutput{Result: result, Open: false}, nil
	}

	conn.Close()
	sb.WriteString("Status: OPEN\n")
	sb.WriteString(fmt.Sprintf("Response time: %dms\n", elapsed.Milliseconds()))

	result := sb.String()
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, PortCheckOutput{Result: result, Open: true}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "portcheck",
		Description: `Check if a TCP port is open on a host.
Tests connectivity by attempting a TCP connection with a configurable timeout.
Returns OPEN/CLOSED status with response time or error details.
Useful for verifying if a server is running, checking firewall rules, or validating deployments.
Supports hostnames, IPv4, and IPv6 addresses.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, PortCheckOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, PortCheckOutput{}, nil
}
