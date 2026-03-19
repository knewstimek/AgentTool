package read

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"agent-tool/common"
	"agent-tool/tools/edit"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// readHashThreshold is the maximum file size for automatically including a hash.
// Files larger than this require a separate call to the checksum tool.
const readHashThreshold = 10 * 1024 * 1024 // 10MB

type ReadInput struct {
	FilePath string `json:"file_path" jsonschema:"Absolute path to the file to read"`
	Offset   int    `json:"offset,omitempty" jsonschema:"Line number to start reading from (1-based). Negative = from end (e.g. -5 = last 5 lines). Default: 1"`
	Limit    int    `json:"limit,omitempty" jsonschema:"Maximum number of lines to read. Default: 0 (all)"`
}

type ReadOutput struct {
	Content    string `json:"content"`
	Encoding   string `json:"encoding"`
	TotalLines int    `json:"total_lines"`
	Hash       string `json:"hash,omitempty"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input ReadInput) (*mcp.CallToolResult, ReadOutput, error) {
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
		return errorResult(fmt.Sprintf("path is a directory, not a file: %s", input.FilePath))
	}

	// .editorconfig charset hint
	hintCharset := edit.FindEditorConfigCharset(input.FilePath)

	// Read with encoding detection
	content, encInfo, err := common.ReadFileWithEncoding(input.FilePath, hintCharset)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to read file: %v", err))
	}

	// Count total lines (allocation-free O(N))
	totalLines := strings.Count(content, "\n") + 1

	var startIdx, endIdx int

	if input.Offset < 0 {
		// Negative index: calculate from the end
		startIdx = totalLines + input.Offset
		if startIdx < 0 {
			startIdx = 0
		}
	} else {
		offset := input.Offset
		if offset < 1 {
			offset = 1
		}
		if offset > totalLines {
			offset = totalLines
		}
		startIdx = offset - 1
	}

	endIdx = totalLines
	if input.Limit > 0 && startIdx+input.Limit < endIdx {
		endIdx = startIdx + input.Limit
	}

	// Process only the needed range with Scanner (saves memory vs full Split)
	var sb strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	for scanner.Scan() {
		if lineNum >= endIdx {
			break
		}
		if lineNum >= startIdx {
			fmt.Fprintf(&sb, "%6d\t%s\n", lineNum+1, scanner.Text())
		}
		lineNum++
	}

	result := sb.String()

	// Add warning if encoding detection confidence is low
	if warning := common.EncodingWarning(encInfo); warning != "" {
		result += warning
	}

	// Add file hash (only for files <= 10MB — use checksum tool for larger files)
	var fileHash string
	if fi.Size() <= readHashThreshold {
		if h, err := common.ComputeFileHash(input.FilePath); err == nil {
			fileHash = h
			result += fmt.Sprintf("\n[sha256: %s]", h)
		}
	}

	out := ReadOutput{
		Content:    result,
		Encoding:   encInfo.Charset,
		TotalLines: totalLines,
		Hash:       fileHash,
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, out, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "read",
		Description: `Reads a file and returns its contents with line numbers.
Encoding-aware: auto-detects file encoding (UTF-8, EUC-KR, Shift-JIS, etc.).
Supports offset/limit for reading specific line ranges.
Negative offset reads from end (e.g. offset=-5 reads last 5 lines).`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, ReadOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, ReadOutput{}, nil
}
