package firewall

import (
	"context"
	"fmt"
	"strings"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type FirewallInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"Filter rules by name or port number"`
}

type FirewallOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input FirewallInput) (*mcp.CallToolResult, FirewallOutput, error) {
	// Remove newlines/control characters (prevent output injection)
	filter := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, strings.TrimSpace(input.Filter))

	output, source, err := getRules(filter)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to query firewall: %v", err))
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Firewall Rules (%s) ===\n\n", source))
	sb.WriteString(output)
	if !strings.HasSuffix(output, "\n") {
		sb.WriteString("\n")
	}

	result := sb.String()
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, FirewallOutput{Result: result}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "firewall",
		Description: `Reads firewall rules (read-only). Linux: iptables/nftables/firewalld. Windows: netsh advfirewall.
Use filter to search by rule name or port number. May require elevated privileges on Linux.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, FirewallOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, FirewallOutput{Result: msg}, nil
}
