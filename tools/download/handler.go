package download

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultTimeoutSec = 60
	maxTimeoutSec     = 600
	defaultMaxSizeMB  = 100
	maxMaxSizeMB      = 2048
	defaultUserAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
)

type DownloadInput struct {
	URL        string            `json:"url" jsonschema:"URL of the file to download,required"`
	OutputPath string            `json:"output_path" jsonschema:"Absolute path to save the downloaded file,required"`
	Headers    map[string]string `json:"headers,omitempty" jsonschema:"Custom HTTP headers (e.g. User-Agent, Referer, Authorization)"`
	Overwrite  interface{}       `json:"overwrite,omitempty" jsonschema:"Overwrite existing file: true or false. Default: false"`
	TimeoutSec int              `json:"timeout_sec,omitempty" jsonschema:"Request timeout in seconds. Default: 60, Max: 600"`
	MaxSizeMB  int               `json:"max_size_mb,omitempty" jsonschema:"Maximum download size in MB. Default: 100, Max: 2048"`
	ProxyURL   string            `json:"proxy_url,omitempty" jsonschema:"HTTP or SOCKS5 proxy URL (e.g. http://proxy:8080, socks5://proxy:1080)"`
	NoDoH      interface{}       `json:"no_doh,omitempty" jsonschema:"Disable DNS over HTTPS: true or false. Default: false (DoH enabled)"`
	NoECH      interface{}       `json:"no_ech,omitempty" jsonschema:"Disable Encrypted Client Hello: true or false. Default: false (ECH enabled)"`
}

type DownloadOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input DownloadInput) (*mcp.CallToolResult, DownloadOutput, error) {
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

	// Validate output path
	if strings.TrimSpace(input.OutputPath) == "" {
		return errorResult("output_path is required")
	}
	input.OutputPath = filepath.Clean(input.OutputPath)
	if !filepath.IsAbs(input.OutputPath) {
		return errorResult("output_path must be an absolute path")
	}

	// Check if file exists
	if !common.FlexBool(input.Overwrite) {
		if _, err := os.Stat(input.OutputPath); err == nil {
			return errorResult(fmt.Sprintf("file already exists: %s (use overwrite=true to replace)", input.OutputPath))
		}
	}

	// Defaults
	if input.TimeoutSec <= 0 {
		input.TimeoutSec = defaultTimeoutSec
	}
	if input.TimeoutSec > maxTimeoutSec {
		return errorResult(fmt.Sprintf("timeout_sec exceeds maximum (%d)", maxTimeoutSec))
	}
	if input.MaxSizeMB <= 0 {
		input.MaxSizeMB = defaultMaxSizeMB
	}
	if input.MaxSizeMB > maxMaxSizeMB {
		return errorResult(fmt.Sprintf("max_size_mb exceeds maximum (%d)", maxMaxSizeMB))
	}
	maxBytes := int64(input.MaxSizeMB) * 1024 * 1024

	noDoH := common.FlexBool(input.NoDoH)
	noECH := common.FlexBool(input.NoECH)

	// Create HTTP client
	client, err := common.NewHTTPClient(common.HTTPClientConfig{
		TimeoutSec: input.TimeoutSec,
		ProxyURL:   input.ProxyURL,
		EnableDoH:  !noDoH && common.GetEnableDoH(),
		EnableECH:  !noECH && common.GetEnableECH(),
	})
	if err != nil {
		return errorResult(fmt.Sprintf("client setup failed: %v", err))
	}

	// Build request
	httpReq, err := http.NewRequestWithContext(ctx, "GET", input.URL, nil)
	if err != nil {
		return errorResult(fmt.Sprintf("request creation failed: %v", err))
	}

	httpReq.Header.Set("User-Agent", defaultUserAgent)
	// Block hop-by-hop headers that could enable request smuggling
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

	// Execute with ECH support
	resp, err := common.DoRequestWithECH(ctx, client, httpReq, !noECH && common.GetEnableECH())
	if err != nil {
		msg := fmt.Sprintf("request failed: %v", err)
		if ssrfWarning != "" {
			msg = ssrfWarning + "\n\n" + msg
		}
		return errorResult(msg)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return errorResult(fmt.Sprintf("HTTP %d: %s", resp.StatusCode, resp.Status))
	}

	// Create parent directories
	dir := filepath.Dir(input.OutputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errorResult(fmt.Sprintf("create directory: %v", err))
	}

	// Write to temp file, then atomic rename
	tmpFile, err := os.CreateTemp(dir, ".agent-tool-download-*.tmp")
	if err != nil {
		return errorResult(fmt.Sprintf("create temp file: %v", err))
	}
	tmpPath := tmpFile.Name()
	renamed := false
	defer func() {
		tmpFile.Close()
		if !renamed {
			os.Remove(tmpPath) // clean up on failure
		}
	}()

	// Copy with size limit
	written, err := io.Copy(tmpFile, io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return errorResult(fmt.Sprintf("download failed: %v", err))
	}
	if written > maxBytes {
		return errorResult(fmt.Sprintf("download exceeds maximum size (%d MB)", input.MaxSizeMB))
	}

	tmpFile.Close()

	// Atomic rename
	if err := os.Rename(tmpPath, input.OutputPath); err != nil {
		return errorResult(fmt.Sprintf("save file: %v", err))
	}
	renamed = true

	// Format result
	ct := resp.Header.Get("Content-Type")
	sizeStr := formatSize(written)
	msg := fmt.Sprintf("Downloaded: %s\nSaved to: %s\nSize: %s\nContent-Type: %s",
		input.URL, input.OutputPath, sizeStr, ct)

	if ssrfWarning != "" {
		msg = ssrfWarning + "\n\n" + msg
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, DownloadOutput{Result: msg}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "download",
		Description: `Download a file from a URL and save it to disk.
Supports binary and text files. For reading web page content as text, use the webfetch tool.
Features: ECH (Encrypted Client Hello) and DoH (DNS over HTTPS) enabled by default.
Supports HTTP and SOCKS5 proxies. SSRF protection blocks private/internal IPs.
Max download size: 100 MB (adjustable via max_size_mb, hard limit 2 GB).`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, DownloadOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, DownloadOutput{}, nil
}

func formatSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
}
