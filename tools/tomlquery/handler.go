package tomlquery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"agent-tool/common"

	"github.com/BurntSushi/toml"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type TOMLQueryInput struct {
	FilePath string `json:"file_path" jsonschema:"Absolute path to the TOML file"`
	Query    string `json:"query" jsonschema:"Dot-notation query path (e.g. dependencies.react, tool.poetry.name, servers[0].host)"`
}

type TOMLQueryOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input TOMLQueryInput) (*mcp.CallToolResult, TOMLQueryOutput, error) {
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	if !filepath.IsAbs(input.FilePath) {
		return errorResult("file_path must be an absolute path")
	}
	if strings.TrimSpace(input.Query) == "" {
		return errorResult("query is required")
	}

	// Symlink check
	if !common.GetAllowSymlinks() {
		if lfi, err := os.Lstat(input.FilePath); err == nil && lfi.Mode()&os.ModeSymlink != 0 {
			return errorResult("symlinks are not allowed (see set_config allow_symlinks)")
		}
	}

	fi, err := os.Stat(input.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("file not found: %s", input.FilePath))
		}
		return errorResult(fmt.Sprintf("cannot access file: %v", err))
	}
	if fi.IsDir() {
		return errorResult("path is a directory, not a file")
	}

	// Size check — TOML parsing inflates memory similarly to JSON
	const maxTOMLSize = 10 * 1024 * 1024 // 10 MB
	maxSize := int64(common.GetMaxFileSize())
	if maxSize > maxTOMLSize {
		maxSize = maxTOMLSize
	}
	if fi.Size() > maxSize {
		return errorResult(fmt.Sprintf("file too large: %d bytes (max: %d bytes). TOML parsing uses significant memory", fi.Size(), maxSize))
	}

	data, err := os.ReadFile(input.FilePath)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot read file: %v", err))
	}

	// Parse TOML — decodes into map[string]interface{} which matches Navigate's expectations.
	// Numbers decode as int64 (not float64 like JSON), datetime as time.Time.
	var root map[string]interface{}
	if _, err := toml.Decode(string(data), &root); err != nil {
		return errorResult(fmt.Sprintf("invalid TOML: %v", err))
	}

	// TOML [[section]] decodes as []map[string]interface{} which Navigate
	// cannot index (expects []interface{}). Recursively normalize.
	normalized := normalizeTOML(root)

	// Navigate query path
	result, err := common.Navigate(normalized, input.Query)
	if err != nil {
		return errorResult(fmt.Sprintf("query error: %v", err))
	}

	// Format output
	typeName := common.TypeName(result)
	var valueStr string
	switch v := result.(type) {
	case string:
		valueStr = fmt.Sprintf("%q", v)
	case nil:
		valueStr = "null"
	case int64:
		valueStr = fmt.Sprintf("%d", v)
	case int:
		valueStr = fmt.Sprintf("%d", v)
	case time.Time:
		valueStr = v.Format(time.RFC3339)
	default:
		pretty, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			valueStr = fmt.Sprintf("%v", result)
		} else {
			valueStr = string(pretty)
		}
	}

	msg := fmt.Sprintf("File: %s\nQuery: %s\nType: %s\n\n%s",
		filepath.Base(input.FilePath), input.Query, typeName, valueStr)

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, TOMLQueryOutput{Result: msg}, nil
}

// normalizeTOML recursively converts typed slices to []interface{}
// so that common.Navigate's array indexing and wildcard work correctly.
// BurntSushi/toml decodes arrays as typed slices ([]int64, []string, etc.),
// not []interface{}, which Navigate expects for array operations.
func normalizeTOML(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		for k, v2 := range val {
			val[k] = normalizeTOML(v2)
		}
		return val
	case []map[string]interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = normalizeTOML(item)
		}
		return result
	case []interface{}:
		for i, v2 := range val {
			val[i] = normalizeTOML(v2)
		}
		return val
	// TOML typed arrays: toml library decodes homogeneous arrays
	// as typed slices, not []interface{}. Convert them so Navigate works.
	case []int64:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = item
		}
		return result
	case []string:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = item
		}
		return result
	case []float64:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = item
		}
		return result
	case []bool:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = item
		}
		return result
	case []time.Time:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = item
		}
		return result
	default:
		return v
	}
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "tomlquery",
		Description: `Query a TOML file using dot-notation paths without loading the entire file into context.
Supports nested keys (a.b.c), array indices ([0], [-1] for last), and wildcards ([*] for all elements).
Examples: "dependencies.react", "tool.poetry.name", "servers[0].host", "servers[*].role".
Returns the matched value with its type. Objects and arrays are pretty-printed as JSON.
Use this to extract specific values from large TOML files to save tokens.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, TOMLQueryOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, TOMLQueryOutput{}, nil
}
