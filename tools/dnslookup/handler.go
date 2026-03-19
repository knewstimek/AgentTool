package dnslookup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"agent-tool/common"

	"github.com/miekg/dns"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultDoHEndpoint = "https://cloudflare-dns.com/dns-query"
	queryTimeout       = 5 * time.Second
	// Fallback DNS server for Windows or when resolv.conf is unavailable
	fallbackDNS = "8.8.8.8:53"
)

// validRecordTypes lists the supported DNS record types.
var validRecordTypes = map[string]uint16{
	"A":     dns.TypeA,
	"AAAA":  dns.TypeAAAA,
	"MX":    dns.TypeMX,
	"CNAME": dns.TypeCNAME,
	"TXT":   dns.TypeTXT,
	"NS":    dns.TypeNS,
	"SOA":   dns.TypeSOA,
}

type DNSLookupInput struct {
	Host        string `json:"host" jsonschema:"Hostname to look up,required"`
	RecordType  string `json:"record_type,omitempty" jsonschema:"DNS record type: A, AAAA, MX, CNAME, TXT, NS, SOA. Default: A"`
	UseDoH      *bool  `json:"use_doh,omitempty" jsonschema:"Use DNS over HTTPS. Default: true"`
	DoHEndpoint string `json:"doh_endpoint,omitempty" jsonschema:"Custom DoH endpoint URL. Default: Cloudflare"`
}

type DNSLookupOutput struct {
	Result string `json:"result"`
}

// dohHTTPClient uses the system resolver to avoid circular dependency
// when resolving the DoH endpoint hostname itself.
var dohHTTPClient = &http.Client{
	Timeout: queryTimeout,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 3 * time.Second,
		}).DialContext,
	},
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input DNSLookupInput) (*mcp.CallToolResult, DNSLookupOutput, error) {
	// Validate host
	input.Host = strings.TrimSpace(input.Host)
	if input.Host == "" {
		return errorResult("host is required")
	}

	// Default and validate record type
	if input.RecordType == "" {
		input.RecordType = "A"
	}
	input.RecordType = strings.ToUpper(strings.TrimSpace(input.RecordType))
	qtype, ok := validRecordTypes[input.RecordType]
	if !ok {
		return errorResult(fmt.Sprintf("invalid record_type: %s (valid: A, AAAA, MX, CNAME, TXT, NS, SOA)", input.RecordType))
	}

	// Default UseDoH to true — pointer type needed because Go's bool zero-value
	// is false, which would silently disable DoH when the field is omitted.
	// Global set_config enable_doh can override the default.
	useDoH := (input.UseDoH == nil || *input.UseDoH) && common.GetEnableDoH()

	// Default DoH endpoint
	if input.DoHEndpoint == "" {
		input.DoHEndpoint = defaultDoHEndpoint
	}

	// Validate custom DoH endpoint to prevent SSRF via arbitrary URL.
	// Check both HTTPS scheme and that the hostname doesn't resolve to private IPs.
	if useDoH && input.DoHEndpoint != defaultDoHEndpoint {
		if !strings.HasPrefix(input.DoHEndpoint, "https://") {
			return errorResult("doh_endpoint must use HTTPS")
		}
		u, err := url.Parse(input.DoHEndpoint)
		if err != nil {
			return errorResult("invalid doh_endpoint URL")
		}
		host := u.Hostname()
		if ip := net.ParseIP(host); ip != nil {
			if common.IsPrivateIP(ip) {
				return errorResult("blocked: DoH endpoint is a private/internal address")
			}
		} else {
			ips, resolveErr := net.DefaultResolver.LookupHost(ctx, host)
			if resolveErr == nil {
				for _, ipStr := range ips {
					if parsed := net.ParseIP(ipStr); parsed != nil && common.IsPrivateIP(parsed) {
						return errorResult("blocked: DoH endpoint resolves to private/internal address")
					}
				}
			}
		}
	}

	// Build DNS query message
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(input.Host), qtype)
	msg.RecursionDesired = true

	queryCtx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var respMsg *dns.Msg
	var err error

	if useDoH {
		respMsg, err = queryDoH(queryCtx, msg, input.DoHEndpoint)
	} else {
		respMsg, err = queryUDP(msg)
	}
	if err != nil {
		return errorResult(fmt.Sprintf("DNS query failed: %s", err))
	}

	if respMsg.Rcode != dns.RcodeSuccess {
		return errorResult(fmt.Sprintf("DNS query returned: %s", dns.RcodeToString[respMsg.Rcode]))
	}

	// Format results
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("DNS lookup: %s (type %s", input.Host, input.RecordType))
	if useDoH {
		sb.WriteString(", DoH")
	} else {
		sb.WriteString(", UDP")
	}
	sb.WriteString(")\n\n")

	if len(respMsg.Answer) == 0 {
		sb.WriteString("No records found.\n")
	} else {
		for _, ans := range respMsg.Answer {
			sb.WriteString(formatRecord(ans))
		}
	}

	result := sb.String()
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, DNSLookupOutput{Result: result}, nil
}

// queryDoH sends a DNS query over HTTPS (RFC 8484).
func queryDoH(ctx context.Context, msg *dns.Msg, endpoint string) (*dns.Msg, error) {
	wireData, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(wireData))
	if err != nil {
		return nil, fmt.Errorf("create DoH request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := dohHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH response status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}

	var respMsg dns.Msg
	if err := respMsg.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack DNS response: %w", err)
	}

	return &respMsg, nil
}

// queryUDP sends a DNS query via UDP to the system resolver.
func queryUDP(msg *dns.Msg) (*dns.Msg, error) {
	server := getSystemDNS()

	client := &dns.Client{
		Net:     "udp",
		Timeout: queryTimeout,
	}

	resp, _, err := client.Exchange(msg, server)
	if err != nil {
		return nil, fmt.Errorf("UDP query to %s: %w", server, err)
	}

	return resp, nil
}

// getSystemDNS reads the system DNS resolver address.
// On Windows, falls back to 8.8.8.8:53 since /etc/resolv.conf doesn't exist.
func getSystemDNS() string {
	if runtime.GOOS == "windows" {
		return fallbackDNS
	}

	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(conf.Servers) == 0 {
		return fallbackDNS
	}

	server := conf.Servers[0]
	port := conf.Port
	if port == "" {
		port = "53"
	}
	return net.JoinHostPort(server, port)
}

// formatRecord formats a single DNS answer record into a human-readable line.
func formatRecord(rr dns.RR) string {
	hdr := rr.Header()
	ttl := hdr.Ttl

	switch r := rr.(type) {
	case *dns.A:
		return fmt.Sprintf("A\t%s\t(TTL: %ds)\n", r.A.String(), ttl)
	case *dns.AAAA:
		return fmt.Sprintf("AAAA\t%s\t(TTL: %ds)\n", r.AAAA.String(), ttl)
	case *dns.MX:
		return fmt.Sprintf("MX\t%s (priority: %d)\t(TTL: %ds)\n", r.Mx, r.Preference, ttl)
	case *dns.CNAME:
		return fmt.Sprintf("CNAME\t%s\t(TTL: %ds)\n", r.Target, ttl)
	case *dns.TXT:
		return fmt.Sprintf("TXT\t%s\t(TTL: %ds)\n", strings.Join(r.Txt, " "), ttl)
	case *dns.NS:
		return fmt.Sprintf("NS\t%s\t(TTL: %ds)\n", r.Ns, ttl)
	case *dns.SOA:
		return fmt.Sprintf("SOA\tns=%s mbox=%s serial=%d refresh=%d retry=%d expire=%d minttl=%d\t(TTL: %ds)\n",
			r.Ns, r.Mbox, r.Serial, r.Refresh, r.Retry, r.Expire, r.Minttl, ttl)
	default:
		return fmt.Sprintf("%s\t%s\t(TTL: %ds)\n", dns.TypeToString[hdr.Rrtype], rr.String(), ttl)
	}
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "dnslookup",
		Description: `Query DNS records for a hostname.
Supports record types: A, AAAA, MX, CNAME, TXT, NS, SOA.
Uses DNS over HTTPS (DoH) by default for privacy and to bypass local DNS filters.
Can also use traditional UDP DNS queries against the system resolver.
Returns record values with TTL information.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, DNSLookupOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, DNSLookupOutput{}, nil
}
