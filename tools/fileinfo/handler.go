package fileinfo

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"agent-tool/common"
	"agent-tool/tools/edit"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type FileInfoInput struct {
	FilePath string `json:"file_path" jsonschema:"Absolute path to the file"`
}

type FileInfoOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input FileInfoInput) (*mcp.CallToolResult, FileInfoOutput, error) {
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	if !filepath.IsAbs(input.FilePath) {
		return errorResult("file_path must be an absolute path")
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

	// Detect encoding
	hintCharset := edit.FindEditorConfigCharset(input.FilePath)
	content, encInfo, err := common.ReadFileWithEncoding(input.FilePath, hintCharset)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to read file: %v", err))
	}

	// Detect line ending
	lineEnding := "LF"
	if strings.Contains(content, "\r\n") {
		lineEnding = "CRLF"
	}

	// Total line count
	totalLines := 1
	for _, c := range content {
		if c == '\n' {
			totalLines++
		}
	}
	if content == "" {
		totalLines = 0
	}

	// Detect indentation
	indent := edit.DetectIndent(input.FilePath, content)
	indentStr := "tabs"
	if !indent.UseTabs {
		indentStr = fmt.Sprintf("spaces-%d", indent.IndentSize)
	}

	// Display BOM indicator
	encName := encInfo.Charset
	if encInfo.HasBOM {
		encName += " (BOM)"
	}

	msg := fmt.Sprintf(`File: %s
Size: %s (%d bytes)
Encoding: %s (confidence: %d%%, source: %s)
Line ending: %s
Indentation: %s
Total lines: %d`,
		input.FilePath,
		formatSize(fi.Size()), fi.Size(),
		encName, encInfo.Confidence, encInfo.UsedSource,
		lineEnding,
		indentStr,
		totalLines,
	)

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, FileInfoOutput{Result: msg}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "file_info",
		Description: `Returns detailed file metadata: size, encoding, line ending, indentation style, and line count.
Uses the same encoding detection as read/edit (chardet + .editorconfig).`,
	}, Handle)
}

func formatSize(bytes int64) string {
	switch {
	case bytes >= 1024*1024*1024:
		return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
	case bytes >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	case bytes >= 1024:
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func errorResult(msg string) (*mcp.CallToolResult, FileInfoOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, FileInfoOutput{Result: msg}, nil
}
