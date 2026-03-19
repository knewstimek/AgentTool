package envvar

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type EnvVarInput struct {
	Name   string `json:"name,omitempty" jsonschema:"Get a specific environment variable by exact name"`
	Filter string `json:"filter,omitempty" jsonschema:"Filter variables by name (case-insensitive partial match)"`
}

type EnvVarOutput struct {
	Result string `json:"result"`
}

// sensitiveKeywords lists variable name keywords whose values should be masked.
// AUTH is too broad (false positives like AUTHOR), so only specific patterns are used.
var sensitiveKeywords = []string{
	"PASSWORD", "PASSWD", "SECRET", "TOKEN", "CREDENTIAL",
	"API_KEY", "APIKEY", "PRIVATE", "ACCESS_KEY", "SIGNING_KEY",
	"AUTH_TOKEN", "AUTH_KEY", "AUTH_SECRET",
}

// safeSuffixes lists suffixes that should not be masked even if a keyword is present.
var safeSuffixes = []string{
	"_PATH", "_FILE", "_DIR", "_HOME", "_ROOT", "_URL", "_URI",
	"_STORE", "_PROVIDER", "_TYPE", "_MODE", "_LEVEL",
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input EnvVarInput) (*mcp.CallToolResult, EnvVarOutput, error) {
	// Look up a specific variable
	if input.Name != "" {
		// Remove newlines (prevent output injection)
		name := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' {
				return -1
			}
			return r
		}, strings.TrimSpace(input.Name))
		val, ok := os.LookupEnv(name)
		if !ok {
			return errorResult(fmt.Sprintf("environment variable not found: %s", name))
		}
		if isSensitive(name) {
			val = maskValue(val)
		}
		msg := fmt.Sprintf("%s=%s", name, val)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, EnvVarOutput{Result: msg}, nil
	}

	// Full or filtered list
	envs := os.Environ()
	filter := strings.ToUpper(strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, input.Filter)))

	var items []string
	for _, env := range envs {
		eqIdx := strings.IndexByte(env, '=')
		if eqIdx < 0 {
			continue
		}
		name := env[:eqIdx]
		value := env[eqIdx+1:]

		if filter != "" && !strings.Contains(strings.ToUpper(name), filter) {
			continue
		}

		if isSensitive(name) {
			value = maskValue(value)
		}

		// Truncate long values (e.g. PATH)
		if len(value) > 500 {
			value = value[:497] + "..."
		}

		items = append(items, fmt.Sprintf("%s=%s", name, value))
	}

	sort.Strings(items)

	var sb strings.Builder
	sb.WriteString("=== Environment Variables ===\n\n")
	for _, item := range items {
		sb.WriteString(item + "\n")
	}
	sb.WriteString(fmt.Sprintf("\nTotal: %d variables shown", len(items)))
	if filter != "" {
		sb.WriteString(fmt.Sprintf(" (filtered from %d)", len(envs)))
	}
	sb.WriteString("\n")

	result := sb.String()
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, EnvVarOutput{Result: result}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "envvar",
		Description: `Reads environment variables. Returns a single variable by name, or lists all with optional filter.
Sensitive values (passwords, tokens, keys) are automatically masked for security.`,
	}, Handle)
}

// isSensitive checks whether a variable name contains sensitive keywords.
func isSensitive(name string) bool {
	upper := strings.ToUpper(name)

	// Exclude from masking if it has a safe suffix
	for _, suffix := range safeSuffixes {
		if strings.HasSuffix(upper, suffix) {
			return false
		}
	}

	// Check keyword matching first
	matched := false
	for _, kw := range sensitiveKeywords {
		if strings.Contains(upper, kw) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}

	// Even if PUBLIC is present, treat as sensitive if SECRET/TOKEN etc. are also present
	// e.g. PUBLIC_SECRET_KEY → sensitive, PUBLIC_KEY → not sensitive
	if strings.Contains(upper, "PUBLIC") {
		// Sensitive if a strong keyword like SECRET, TOKEN, PASSWORD is also present
		strongKeywords := []string{"SECRET", "PASSWORD", "PASSWD", "TOKEN", "CREDENTIAL", "PRIVATE"}
		for _, sk := range strongKeywords {
			if strings.Contains(upper, sk) {
				return true
			}
		}
		return false
	}

	return true
}

// maskValue partially masks a value.
// Short values (8 chars or less) are fully masked; otherwise only the first 4 chars are shown.
func maskValue(val string) string {
	if len(val) <= 8 {
		return "***"
	}
	return val[:4] + "***"
}

func errorResult(msg string) (*mcp.CallToolResult, EnvVarOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, EnvVarOutput{Result: msg}, nil
}
