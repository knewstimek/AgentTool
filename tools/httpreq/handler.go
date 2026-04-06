package httpreq

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultTimeoutSec  = 30
	maxTimeoutSec      = 120
	defaultMaxRespKB   = 512
	maxMaxRespKB       = 2048
	defaultContentType = "application/json"
	defaultUserAgent   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
)

var allowedMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true,
}

type HTTPReqInput struct {
	URL            string            `json:"url" jsonschema:"URL to send the request to,required"`
	Method         string            `json:"method" jsonschema:"HTTP method: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS,required"`
	Body           string            `json:"body,omitempty" jsonschema:"Request body (string). Typically JSON for API calls"`
	Headers        map[string]string `json:"headers,omitempty" jsonschema:"Custom HTTP headers (e.g. Authorization, Accept)"`
	ContentType    string            `json:"content_type,omitempty" jsonschema:"Content-Type header. Default: application/json"`
	TimeoutSec     interface{}       `json:"timeout_sec,omitempty" jsonschema:"Request timeout in seconds. Default: 30, Max: 120"`
	ProxyURL       string            `json:"proxy_url,omitempty" jsonschema:"HTTP or SOCKS5 proxy URL (e.g. http://proxy:8080, socks5://proxy:1080)"`
	NoDoH          interface{}       `json:"no_doh,omitempty" jsonschema:"Disable DNS over HTTPS: true or false. Default: false (DoH enabled)"`
	NoECH          interface{}       `json:"no_ech,omitempty" jsonschema:"Disable Encrypted Client Hello: true or false. Default: false (ECH enabled)"`
	MaxResponseKB  interface{}       `json:"max_response_kb,omitempty" jsonschema:"Maximum response body size in KB. Default: 512, Max: 2048"`
}

type HTTPReqOutput struct {
	Result     string `json:"result"`
	StatusCode int    `json:"status_code"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input HTTPReqInput) (*mcp.CallToolResult, HTTPReqOutput, error) {
	// Validate URL
	if strings.TrimSpace(input.URL) == "" {
		return errorResult("url is required")
	}
	parsedURL, err := url.Parse(input.URL)
	if err != nil {
		return errorResult(fmt.Sprintf("invalid URL: %v", err))
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return errorResult("only http and https URLs are supported")
	}

	// SSRF policy check — warn on private IP access (helps detect prompt injection)
	_, ssrfWarning, ssrfErr := common.CheckHostSSRF(ctx, parsedURL.Hostname(), common.GetAllowHTTPPrivate(), "http")
	if ssrfErr != nil {
		return errorResult(ssrfErr.Error())
	}

	// Validate method
	input.Method = strings.ToUpper(strings.TrimSpace(input.Method))
	if input.Method == "" {
		return errorResult("method is required")
	}
	if !allowedMethods[input.Method] {
		return errorResult(fmt.Sprintf("unsupported method: %s (supported: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)", input.Method))
	}

	// DLP: scan outbound body for sensitive data before transmission.
	// All methods with a body are checked — DELETE/GET can also carry bodies
	// that exfiltrate secrets to attacker-controlled servers.
	if input.Body != "" {
		if matches := common.ScanSensitiveData(input.Body); len(matches) > 0 {
			msg := common.FormatDLPBlock(matches)
			return errorResult(msg)
		}
	}

	// Defaults
	timeoutSec, ok := common.FlexInt(input.TimeoutSec)
	if !ok {
		return errorResult("timeout_sec must be an integer")
	}
	maxResponseKB, ok := common.FlexInt(input.MaxResponseKB)
	if !ok {
		return errorResult("max_response_kb must be an integer")
	}
	if timeoutSec <= 0 {
		timeoutSec = defaultTimeoutSec
	}
	if timeoutSec > maxTimeoutSec {
		return errorResult(fmt.Sprintf("timeout_sec exceeds maximum (%d)", maxTimeoutSec))
	}
	if maxResponseKB <= 0 {
		maxResponseKB = defaultMaxRespKB
	}
	if maxResponseKB > maxMaxRespKB {
		return errorResult(fmt.Sprintf("max_response_kb exceeds maximum (%d)", maxMaxRespKB))
	}
	if input.ContentType == "" {
		input.ContentType = defaultContentType
	}
	maxRespBytes := int64(maxResponseKB) * 1024

	noDoH := common.FlexBool(input.NoDoH)
	noECH := common.FlexBool(input.NoECH)

	// Create HTTP client
	client, err := common.NewHTTPClient(common.HTTPClientConfig{
		TimeoutSec: timeoutSec,
		ProxyURL:   input.ProxyURL,
		EnableDoH:  !noDoH && common.GetEnableDoH(),
		EnableECH:  !noECH && common.GetEnableECH(),
	})
	if err != nil {
		return errorResult(fmt.Sprintf("client setup failed: %v", err))
	}

	// Build request
	var bodyReader io.Reader
	if input.Body != "" {
		bodyReader = strings.NewReader(input.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, input.Method, input.URL, bodyReader)
	if err != nil {
		return errorResult(fmt.Sprintf("request creation failed: %v", err))
	}

	httpReq.Header.Set("User-Agent", defaultUserAgent)
	if input.Body != "" {
		httpReq.Header.Set("Content-Type", input.ContentType)
	}
	// Apply custom headers, but block hop-by-hop headers that could
	// interfere with transport-level behavior or enable request smuggling.
	for k, v := range input.Headers {
		if strings.TrimSpace(k) == "" {
			continue
		}
		lower := strings.ToLower(k)
		if lower == "host" || lower == "content-length" || lower == "transfer-encoding" {
			continue
		}
		httpReq.Header.Set(k, v)
	}

	// Execute
	resp, err := common.DoRequestWithECH(ctx, client, httpReq, !noECH && common.GetEnableECH())
	if err != nil {
		msg := fmt.Sprintf("request failed: %v", err)
		if ssrfWarning != "" {
			msg = ssrfWarning + "\n\n" + msg
		}
		return errorResult(msg)
	}
	defer resp.Body.Close()

	// Format response header
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP %s %s\n", input.Method, input.URL))
	sb.WriteString(fmt.Sprintf("Status: %s\n", resp.Status))

	ct := resp.Header.Get("Content-Type")
	if ct != "" {
		sb.WriteString(fmt.Sprintf("Content-Type: %s\n", ct))
	}
	if resp.ContentLength >= 0 {
		sb.WriteString(fmt.Sprintf("Content-Length: %d\n", resp.ContentLength))
	}

	// HEAD requests have no body
	if input.Method == "HEAD" {
		result := sb.String()
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: result}},
		}, HTTPReqOutput{Result: result, StatusCode: resp.StatusCode}, nil
	}

	// Read response body
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes+1))
	if err != nil {
		return errorResult(fmt.Sprintf("read response: %v", err))
	}

	truncated := int64(len(body)) > maxRespBytes
	if truncated {
		body = body[:maxRespBytes]
	}

	sb.WriteString("\n")

	// Show body if text-like, otherwise just report size
	if isBinaryContent(ct, body) {
		sb.WriteString(fmt.Sprintf("[Binary response: %d bytes, Content-Type: %s]", len(body), ct))
	} else {
		sb.WriteString(string(body))
	}

	if truncated {
		sb.WriteString(fmt.Sprintf("\n\n[Truncated: response exceeded %d KB]", input.MaxResponseKB))
	}

	result := sb.String()
	if ssrfWarning != "" {
		result = ssrfWarning + "\n\n" + result
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
		IsError: resp.StatusCode >= 400,
	}, HTTPReqOutput{Result: result, StatusCode: resp.StatusCode}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "httpreq",
		Description: `Execute HTTP requests with any method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS).
Ideal for testing APIs, webhooks, and web services during development.
Features: ECH (Encrypted Client Hello) and DoH (DNS over HTTPS) enabled by default.
Supports custom headers, request body, and HTTP/SOCKS5 proxies.
SSRF protection blocks private/internal IPs. Response body is truncated at max_response_kb.
For fetching web pages as text, use webfetch. For downloading files, use download.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, HTTPReqOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, HTTPReqOutput{}, nil
}

// isBinaryContent detects binary responses by checking Content-Type and
// whether the body contains valid UTF-8 text.
func isBinaryContent(ct string, body []byte) bool {
	ct = strings.ToLower(ct)
	if strings.HasPrefix(ct, "text/") {
		return false
	}
	if strings.Contains(ct, "json") || strings.Contains(ct, "xml") ||
		strings.Contains(ct, "javascript") || strings.Contains(ct, "yaml") {
		return false
	}
	if strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "audio/") ||
		strings.HasPrefix(ct, "video/") {
		return true
	}
	// Unknown content type — check if body is valid UTF-8
	return !utf8.Valid(body)
}
