package write

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"agent-tool/common"
	"agent-tool/tools/edit"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type WriteInput struct {
	FilePath string `json:"file_path" jsonschema:"Absolute path to the file to write"`
	Content  string `json:"content" jsonschema:"Content to write to the file"`
}

type WriteOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input WriteInput) (*mcp.CallToolResult, WriteOutput, error) {
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	if !filepath.IsAbs(input.FilePath) {
		return errorResult("file_path must be an absolute path")
	}

	// Auto-create directories
	dir := filepath.Dir(input.FilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errorResult(fmt.Sprintf("failed to create directory: %v", err))
	}

	// Preserve encoding info if existing file exists
	var encInfo common.EncodingInfo

	if fi, err := os.Stat(input.FilePath); err == nil {
		if fi.IsDir() {
			return errorResult(fmt.Sprintf("path is a directory: %s", input.FilePath))
		}
		// Detect encoding of existing file
		hintCharset := edit.FindEditorConfigCharset(input.FilePath)
		_, encInfo, err = common.ReadFileWithEncoding(input.FilePath, hintCharset)
		if err != nil {
			// Can still write even if read fails (default UTF-8)
			encInfo = common.EncodingInfo{Charset: "UTF-8"}
		}
	} else {
		// New file: check .editorconfig charset hint, default to UTF-8
		hintCharset := edit.FindEditorConfigCharset(input.FilePath)
		if hintCharset != "" {
			encInfo = common.EncodingInfo{Charset: hintCharset}
		} else {
			encInfo = common.EncodingInfo{Charset: "UTF-8"}
		}
	}

	// Write file
	if err := common.WriteFileWithEncoding(input.FilePath, input.Content, encInfo); err != nil {
		return errorResult(fmt.Sprintf("failed to write file: %v", err))
	}

	msg := fmt.Sprintf("OK: file written (%s, encoding=%s)", input.FilePath, encInfo.Charset)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, WriteOutput{Result: msg}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "write",
		Description: `Creates or overwrites a file with the given content.
Encoding-aware: preserves original encoding for existing files, uses .editorconfig hints for new files.
Auto-creates parent directories if they don't exist.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, WriteOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, WriteOutput{Result: msg}, nil
}
