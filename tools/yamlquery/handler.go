package yamlquery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"
)

type YAMLQueryInput struct {
	FilePath string `json:"file_path,omitempty" jsonschema:"Absolute path to the YAML file"`
	Path     string `json:"path,omitempty" jsonschema:"Alias for file_path"`
	Query    string `json:"query" jsonschema:"Dot-notation query path (e.g. services.web.ports[0], spec.containers[*].image)"`
}

type YAMLQueryOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input YAMLQueryInput) (*mcp.CallToolResult, YAMLQueryOutput, error) {
	if input.FilePath == "" {
		input.FilePath = input.Path
	}
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

	// Size check — YAML parsing inflates memory similarly to JSON
	const maxYAMLSize = 10 * 1024 * 1024 // 10 MB
	maxSize := int64(common.GetMaxFileSize())
	if maxSize > maxYAMLSize {
		maxSize = maxYAMLSize
	}
	if fi.Size() > maxSize {
		return errorResult(fmt.Sprintf("file too large: %d bytes (max: %d bytes). YAML parsing uses significant memory", fi.Size(), maxSize))
	}

	// YAML is always UTF-8 per spec, no encoding detection needed
	data, err := os.ReadFile(input.FilePath)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot read file: %v", err))
	}

	// Parse YAML
	var root interface{}
	if err := yaml.Unmarshal(data, &root); err != nil {
		return errorResult(fmt.Sprintf("invalid YAML: %v", err))
	}

	// yaml.v3 may produce map[interface{}]interface{} for non-string keys;
	// normalize to map[string]interface{} for common.Navigate compatibility.
	root = normalizeYAML(root)

	// Navigate query path
	result, err := common.Navigate(root, input.Query)
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
	}, YAMLQueryOutput{Result: msg}, nil
}

// normalizeYAML recursively converts map[interface{}]interface{} (produced by
// yaml.v3 for non-string keys) to map[string]interface{} so that
// common.Navigate can handle the data uniformly.
func normalizeYAML(v interface{}) interface{} {
	switch val := v.(type) {
	case map[interface{}]interface{}:
		m := make(map[string]interface{}, len(val))
		for k, v2 := range val {
			m[fmt.Sprintf("%v", k)] = normalizeYAML(v2)
		}
		return m
	case map[string]interface{}:
		for k, v2 := range val {
			val[k] = normalizeYAML(v2)
		}
		return val
	case []interface{}:
		for i, v2 := range val {
			val[i] = normalizeYAML(v2)
		}
		return val
	default:
		return v
	}
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "yamlquery",
		Description: `Query a YAML file using dot-notation paths without loading the entire file into context.
Supports nested keys (a.b.c), array indices ([0], [-1] for last), and wildcards ([*] for all elements).
Examples: "services.web.ports[0]", "spec.containers[*].image", "database.host".
Returns the matched value with its type. Objects and arrays are pretty-printed as JSON.
Use this to extract specific values from large YAML files to save tokens.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, YAMLQueryOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, YAMLQueryOutput{}, nil
}
