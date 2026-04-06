package jsonquery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type JSONQueryInput struct {
	FilePath string `json:"file_path,omitempty" jsonschema:"Absolute path to the JSON file"`
	Path     string `json:"path,omitempty" jsonschema:"Alias for file_path"`
	Query    string `json:"query" jsonschema:"Dot-notation query path (e.g. dependencies.react, items[0].name, items[*].id)"`
}

type JSONQueryOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input JSONQueryInput) (*mcp.CallToolResult, JSONQueryOutput, error) {
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

	// Size check — JSON parsing inflates memory 5-20x vs raw file size,
	// so use a stricter limit than the general file size setting.
	const maxJSONSize = 10 * 1024 * 1024 // 10 MB
	maxSize := int64(common.GetMaxFileSize())
	if maxSize > maxJSONSize {
		maxSize = maxJSONSize
	}
	if fi.Size() > maxSize {
		return errorResult(fmt.Sprintf("file too large: %d bytes (max: %d bytes). JSON parsing uses 5-20x more memory than file size", fi.Size(), maxSize))
	}

	data, err := os.ReadFile(input.FilePath)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot read file: %v", err))
	}

	// Parse JSON
	var root interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return errorResult(fmt.Sprintf("invalid JSON: %v", err))
	}

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
	}, JSONQueryOutput{Result: msg}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "jsonquery",
		Description: `Query a JSON file using dot-notation paths without loading the entire file into context.
Supports nested keys (a.b.c), array indices ([0], [-1] for last), and wildcards ([*] for all elements).
Examples: "dependencies.react", "scripts.build", "items[0].name", "users[*].email".
Returns the matched value with its type. Objects and arrays are pretty-printed.
Use this to extract specific values from large JSON files to save tokens.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, JSONQueryOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, JSONQueryOutput{}, nil
}
