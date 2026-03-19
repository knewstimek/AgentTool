package tlscheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultPort       = 443
	defaultTimeoutSec = 10
	maxTimeoutSec     = 30
)

type TLSCheckInput struct {
	Host       string `json:"host" jsonschema:"Hostname or IP address to check,required"`
	Port       int    `json:"port,omitempty" jsonschema:"Port number. Default: 443"`
	TimeoutSec int    `json:"timeout_sec,omitempty" jsonschema:"Connection timeout in seconds. Default: 10, Max: 30"`
}

type TLSCheckOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input TLSCheckInput) (*mcp.CallToolResult, TLSCheckOutput, error) {
	if strings.TrimSpace(input.Host) == "" {
		return errorResult("host is required")
	}

	port := input.Port
	if port <= 0 {
		port = defaultPort
	}
	if port > 65535 {
		return errorResult(fmt.Sprintf("invalid port: %d (must be 1-65535)", port))
	}

	timeoutSec := input.TimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = defaultTimeoutSec
	}
	if timeoutSec > maxTimeoutSec {
		return errorResult(fmt.Sprintf("timeout_sec exceeds maximum (%d)", maxTimeoutSec))
	}

	// Block cloud metadata IPs — prevents using TLS check as an SSRF probe
	// against cloud metadata endpoints. Private/internal IPs are allowed
	// since checking internal services is a legitimate diagnostic use case.
	if ip := net.ParseIP(input.Host); ip != nil {
		if common.IsCloudMetadataIP(ip) {
			return errorResult(fmt.Sprintf("blocked: %s is a cloud metadata address", input.Host))
		}
	} else {
		ips, resolveErr := net.DefaultResolver.LookupHost(ctx, input.Host)
		if resolveErr == nil {
			for _, ipStr := range ips {
				if parsed := net.ParseIP(ipStr); parsed != nil && common.IsCloudMetadataIP(parsed) {
					return errorResult(fmt.Sprintf("blocked: %s resolves to cloud metadata address %s", input.Host, ipStr))
				}
			}
		}
	}

	addr := net.JoinHostPort(input.Host, strconv.Itoa(port))
	timeout := time.Duration(timeoutSec) * time.Second

	dialer := &net.Dialer{Timeout: timeout}
	tlsConfig := &tls.Config{
		// ServerName must be the original hostname for SNI (not the resolved IP)
		ServerName: input.Host,
		MinVersion: tls.VersionTLS12,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return errorResult(fmt.Sprintf("TLS connection failed to %s: %v", addr, err))
	}
	defer conn.Close()

	state := conn.ConnectionState()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("TLS Check: %s\n", addr))
	sb.WriteString(fmt.Sprintf("TLS Version: %s\n", tlsVersionName(state.Version)))
	sb.WriteString(fmt.Sprintf("Cipher Suite: %s\n", tls.CipherSuiteName(state.CipherSuite)))

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]

		sb.WriteString(fmt.Sprintf("\nCertificate:\n"))
		sb.WriteString(fmt.Sprintf("  Subject CN: %s\n", cert.Subject.CommonName))
		sb.WriteString(fmt.Sprintf("  Issuer CN:  %s\n", cert.Issuer.CommonName))
		sb.WriteString(fmt.Sprintf("  Not Before: %s\n", cert.NotBefore.UTC().Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("  Not After:  %s\n", cert.NotAfter.UTC().Format(time.RFC3339)))

		daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
		if daysUntilExpiry < 0 {
			sb.WriteString(fmt.Sprintf("  Status:     EXPIRED (%d days ago)\n", -daysUntilExpiry))
		} else if daysUntilExpiry <= 30 {
			sb.WriteString(fmt.Sprintf("  Status:     EXPIRING SOON (%d days remaining)\n", daysUntilExpiry))
		} else {
			sb.WriteString(fmt.Sprintf("  Status:     Valid (%d days remaining)\n", daysUntilExpiry))
		}

		if len(cert.DNSNames) > 0 {
			sb.WriteString(fmt.Sprintf("  SANs:       %s\n", strings.Join(cert.DNSNames, ", ")))
		}
	} else {
		sb.WriteString("\nNo peer certificates received\n")
	}

	result := sb.String()
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, TLSCheckOutput{Result: result}, nil
}

// tlsVersionName returns a human-readable name for a TLS version constant.
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "tlscheck",
		Description: `Checks TLS certificate and connection details for a host.
Returns certificate subject, issuer, expiry, SANs, TLS version, and cipher suite.
Useful for verifying SSL certificates, checking expiry dates, and debugging TLS issues.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, TLSCheckOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, TLSCheckOutput{}, nil
}
