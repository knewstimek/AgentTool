package externalip

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// IPv4 providers — return IPv4 address only.
var ipv4Providers = []string{
	"https://api.ipify.org",
	"https://ipv4.icanhazip.com",
}

// IPv6 providers — return IPv6 address (fail if no IPv6 connectivity).
var ipv6Providers = []string{
	"https://api64.ipify.org",
	"https://ipv6.icanhazip.com",
}

const timeoutSec = 5

type ExternalIPInput struct{}

type ExternalIPOutput struct {
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input ExternalIPInput) (*mcp.CallToolResult, ExternalIPOutput, error) {
	client, err := common.NewHTTPClient(common.HTTPClientConfig{
		TimeoutSec: timeoutSec,
		EnableDoH:  true,
		EnableECH:  true,
	})
	if err != nil {
		return errorResult(fmt.Sprintf("client setup failed: %v", err))
	}

	// Query IPv4 and IPv6 independently
	ipv4 := queryProviders(ctx, client, ipv4Providers)
	ipv6 := queryProviders(ctx, client, ipv6Providers)

	// IPv6 response from api64.ipify.org may return IPv4 if no IPv6 available;
	// deduplicate by clearing ipv6 when it matches ipv4.
	if ipv6 != "" && ipv6 == ipv4 {
		ipv6 = ""
	}

	if ipv4 == "" && ipv6 == "" {
		return errorResult("failed to detect external IP (all providers unreachable)")
	}

	var sb strings.Builder
	if ipv4 != "" {
		sb.WriteString(fmt.Sprintf("External IPv4: %s\n", ipv4))
	}
	if ipv6 != "" {
		sb.WriteString(fmt.Sprintf("External IPv6: %s\n", ipv6))
	} else {
		sb.WriteString("External IPv6: not available\n")
	}

	result := strings.TrimRight(sb.String(), "\n")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, ExternalIPOutput{IPv4: ipv4, IPv6: ipv6}, nil
}

// queryProviders tries each provider in order and returns the first successful IP.
func queryProviders(ctx context.Context, client *http.Client, providers []string) string {
	for _, provider := range providers {
		ip, err := fetchIP(ctx, client, provider)
		if err != nil {
			continue
		}
		return ip
	}
	return ""
}

func fetchIP(ctx context.Context, client *http.Client, providerURL string) (string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", providerURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := common.DoRequestWithECH(ctx, client, httpReq, true)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d from %s", resp.StatusCode, providerURL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}

	ip := strings.TrimSpace(string(body))
	if ip == "" {
		return "", fmt.Errorf("empty response from %s", providerURL)
	}
	// Validate that the response is actually an IP address
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid IP response from %s", providerURL)
	}
	return ip, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "externalip",
		Description: `Returns your external (public) IP address (both IPv4 and IPv6).
Queries dedicated IPv4 and IPv6 detection services with automatic fallback.
IPv6 shows "not available" when the network has no IPv6 connectivity.
Useful for SSH configuration, firewall rules, or verifying VPN/proxy status.
No parameters required.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, ExternalIPOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, ExternalIPOutput{}, nil
}
