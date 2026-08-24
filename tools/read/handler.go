package read

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"agent-tool/common"
	"agent-tool/tools/edit"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// imageExts maps file extensions to MIME types for image files.
var imageExts = map[string]string{
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".gif":  "image/gif",
	".bmp":  "image/bmp",
	".webp": "image/webp",
	".ico":  "image/x-icon",
	".svg":  "image/svg+xml",
	".tiff": "image/tiff",
	".tif":  "image/tiff",
}

// maxImageSize is the maximum image file size we'll return as base64 (20MB).
const maxImageSize = 20 * 1024 * 1024

// readHashThreshold is the maximum file size for automatically including a hash.
// Files larger than this require a separate call to the checksum tool.
const readHashThreshold = 10 * 1024 * 1024 // 10MB

type ReadInput struct {
	FilePath       string `json:"file_path,omitempty" jsonschema:"Absolute or workspace-relative path to the file to read"`
	Path           string `json:"path,omitempty" jsonschema:"Compatibility alias for file_path; prefer file_path"`
	Offset         any    `json:"offset,omitempty" jsonschema:"Line offset. Integer (1-based, negative=from end), string range 'start-end', or [start,end] array. Default: 1"`
	Limit          *int   `json:"limit,omitempty" jsonschema:"Maximum lines to return. Default: 400. Set 0 or all=true to remove the line limit; the character budget still applies"`
	StartLine      *int   `json:"start_line,omitempty" jsonschema:"Compatibility alias for offset; prefer offset"`
	EndLine        *int   `json:"end_line,omitempty" jsonschema:"Inclusive end line used with start_line"`
	All            bool   `json:"all,omitempty" jsonschema:"Remove the default line limit. The max_output_chars safety budget still applies. Default: false"`
	MaxOutputChars int    `json:"max_output_chars,omitempty" jsonschema:"Maximum returned text characters. Default: 32768, Max: 131072"`
	MaxLineChars   int    `json:"max_line_chars,omitempty" jsonschema:"Maximum characters returned from one line. Default: 4000, Max: 32768"`
	IncludeHash    *bool  `json:"include_hash,omitempty" jsonschema:"Include SHA-256 for optimistic edit concurrency. Default: true"`
}

type ReadOutput struct {
	Content       string `json:"content"`
	Encoding      string `json:"encoding"`
	TotalLines    int    `json:"total_lines"`
	Hash          string `json:"hash,omitempty"`
	ReturnedLines int    `json:"returned_lines"`
	Truncated     bool   `json:"truncated"`
	NextOffset    int    `json:"next_offset,omitempty"`
}

const (
	defaultLineLimit    = 400
	defaultMaxLineChars = 4000
)

// parseFlexOffset accepts integer, "N", "N-M" range string, "[N, M]" string,
// or [N, M] array. Agents sometimes pass offset as a string or array instead
// of a plain integer; this function normalizes all forms.
// Returns (offset, rangeLimit). rangeLimit > 0 indicates a range was given.
func parseFlexOffset(v any) (int, int, error) {
	switch val := v.(type) {
	case nil:
		return 0, 0, nil
	case float64:
		return int(val), 0, nil
	case int:
		return val, 0, nil
	case string:
		val = strings.TrimSpace(val)
		if val == "" {
			return 0, 0, nil
		}
		// Strip array brackets: "[370, 396]" -> "370, 396"
		if len(val) >= 2 && val[0] == '[' && val[len(val)-1] == ']' {
			val = strings.TrimSpace(val[1 : len(val)-1])
		}
		// Comma-separated range: "370, 396"
		if parts := strings.SplitN(val, ",", 2); len(parts) == 2 {
			s, e1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			e, e2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if e1 == nil && e2 == nil {
				if e < s {
					s, e = e, s
				}
				return s, e - s + 1, nil
			}
		}
		// Dash range: "370-396" (parts[0]!="" prevents matching negative like "-5")
		if parts := strings.SplitN(val, "-", 2); len(parts) == 2 && parts[0] != "" {
			s, e1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			e, e2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if e1 == nil && e2 == nil {
				if e < s {
					s, e = e, s
				}
				return s, e - s + 1, nil
			}
		}
		// Plain number
		n, err := strconv.Atoi(val)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid offset %q -- use integer, 'start-end', or [start, end]", v)
		}
		return n, 0, nil
	case []interface{}:
		if len(val) == 2 {
			s, ok1 := asInt(val[0])
			e, ok2 := asInt(val[1])
			if ok1 && ok2 {
				if e < s {
					s, e = e, s
				}
				return s, e - s + 1, nil
			}
		}
		return 0, 0, fmt.Errorf("invalid offset array -- expected [start, end] integers")
	default:
		return 0, 0, fmt.Errorf("invalid offset type %T -- use integer or string", v)
	}
}

func asInt(v interface{}) (int, bool) {
	switch val := v.(type) {
	case float64:
		return int(val), true
	case int:
		return val, true
	default:
		return 0, false
	}
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input ReadInput) (*mcp.CallToolResult, ReadOutput, error) {
	// Accept "path" as an alias for "file_path"
	if input.FilePath == "" {
		input.FilePath = input.Path
	}

	// Accept start_line/end_line as aliases for offset/limit
	if input.StartLine != nil && input.Offset == nil {
		input.Offset = *input.StartLine
	}
	if input.EndLine != nil {
		startLine := 1
		if input.StartLine != nil {
			startLine = *input.StartLine
		}
		if *input.EndLine >= startLine {
			limit := *input.EndLine - startLine + 1
			input.Limit = &limit
		}
	}
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	resolvedPath, err := common.ResolveRequestPath(ctx, req, input.FilePath)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot resolve path: %v", err))
	}
	input.FilePath = resolvedPath

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

	// Image files: return as MCP ImageContent (base64-encoded)
	ext := strings.ToLower(filepath.Ext(input.FilePath))
	if mime, isImage := imageExts[ext]; isImage {
		return handleImage(input.FilePath, fi, mime)
	}

	// .editorconfig charset hint
	hintCharset := edit.FindEditorConfigCharset(input.FilePath)

	// Read with encoding detection
	content, encInfo, err := common.ReadFileWithEncoding(input.FilePath, hintCharset)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to read file: %v", err))
	}

	// Match bufio.ScanLines semantics: a final newline terminates the last line
	// and does not create a phantom continuation line.
	totalLines := common.TextLineCount(content)

	offset, rangeLimit, err := parseFlexOffset(input.Offset)
	if err != nil {
		return errorResult(err.Error())
	}

	limit := 0
	limitProvided := input.Limit != nil
	if limitProvided {
		limit = *input.Limit
		if limit < 0 {
			return errorResult("limit must be non-negative")
		}
	}
	// Range (e.g. "100-200") sets limit when explicit limit is not provided
	if rangeLimit > 0 && !limitProvided {
		limit = rangeLimit
		limitProvided = true
	}
	if !limitProvided && !input.All {
		limit = defaultLineLimit
	}

	maxOutputChars := input.MaxOutputChars
	if maxOutputChars <= 0 {
		maxOutputChars = common.DefaultOutputChars
	}
	if maxOutputChars > common.HardOutputChars {
		return errorResult(fmt.Sprintf("max_output_chars must be at most %d", common.HardOutputChars))
	}
	maxLineChars := input.MaxLineChars
	if maxLineChars <= 0 {
		maxLineChars = defaultMaxLineChars
	}
	if maxLineChars > common.DefaultOutputChars {
		return errorResult(fmt.Sprintf("max_line_chars must be at most %d", common.DefaultOutputChars))
	}

	var startIdx, endIdx int

	if totalLines == 0 {
		startIdx = 0
	} else if offset < 0 {
		// Negative index: calculate from the end
		startIdx = totalLines + offset
		if startIdx < 0 {
			startIdx = 0
		}
	} else {
		if offset < 1 {
			offset = 1
		}
		if offset > totalLines {
			offset = totalLines
		}
		startIdx = offset - 1
	}

	endIdx = totalLines
	if limit > 0 && startIdx+limit < endIdx {
		endIdx = startIdx + limit
	}

	// Process only the needed range. The scanner buffer is raised to the decoded
	// file size so a single long line is handled explicitly by max_line_chars
	// instead of disappearing behind Scanner's 64 KiB default token limit.
	var sb strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 64*1024), len(content)+1)
	lineNum := 0
	returnedLines := 0
	outputTruncated := false
	lineTruncated := false
	nextOffset := 0
	contentBudget := maxOutputChars - 512 // reserve room for metadata/footer
	if contentBudget < 256 {
		contentBudget = maxOutputChars
	}
	usedChars := 0
	for scanner.Scan() {
		if lineNum >= endIdx {
			break
		}
		if lineNum >= startIdx {
			lineText, wasLineTruncated := common.TruncateRunes(scanner.Text(), maxLineChars, "… [line truncated]")
			lineTruncated = lineTruncated || wasLineTruncated
			formatted := fmt.Sprintf("%6d\t%s\n", lineNum+1, lineText)
			if !common.AppendWithinRuneBudget(&sb, &usedChars, formatted, contentBudget) {
				outputTruncated = true
				nextOffset = lineNum + 1
				break
			}
			returnedLines++
		}
		lineNum++
	}
	if err := scanner.Err(); err != nil {
		// bufio.Scanner default token limit is 64KB per line.
		// Binary files, minified JS, or data files often have no newlines and
		// exceed this limit. Return an actionable error instead of empty output.
		msg := fmt.Sprintf(
			"cannot read %s as text: a line exceeds 64KB (likely binary, minified, or single-line data file).\n"+
				"- Binary files: use the analyze tool to inspect structure\n"+
				"- Minified/concatenated code: use download to get the raw file\n"+
				"- Large single-line data: use grep to search for specific content\n"+
				"(scanner error: %v)",
			filepath.Base(input.FilePath), err,
		)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
			IsError: true,
		}, ReadOutput{}, nil
	}

	if nextOffset == 0 && endIdx < totalLines {
		nextOffset = endIdx + 1
	}
	truncated := outputTruncated || endIdx < totalLines || lineTruncated

	// Add file hash only when requested. It is useful with edit.expected_hash,
	// but callers can disable it when reading many short-lived files.
	var fileHash string
	includeHash := input.IncludeHash == nil || *input.IncludeHash
	if includeHash && fi.Size() <= readHashThreshold {
		if h, err := common.ComputeFileHash(input.FilePath); err == nil {
			fileHash = h
		}
	}

	if warning := common.EncodingWarning(encInfo); warning != "" {
		sb.WriteString(warning)
	}
	firstLine, lastLine := startIdx+1, startIdx+returnedLines
	if returnedLines == 0 {
		firstLine, lastLine = 0, 0
	}
	footer := fmt.Sprintf("\n[read: lines=%d-%d/%d; returned=%d; truncated=%t; encoding=%s",
		firstLine, lastLine, totalLines, returnedLines, truncated, encInfo.Charset)
	if nextOffset > 0 {
		footer += fmt.Sprintf("; next_offset=%d", nextOffset)
	}
	if lineTruncated {
		footer += "; line_truncated=true; raise max_line_chars to inspect full long lines"
	}
	if fileHash != "" {
		footer += fmt.Sprintf("; sha256=%s", fileHash)
	}
	footer += "]"
	sb.WriteString(footer)
	result, finalTruncated := common.TruncateRunes(sb.String(), maxOutputChars,
		fmt.Sprintf("\n[truncated=true; next_offset=%d]", max(startIdx+returnedLines+1, 1)))
	truncated = truncated || finalTruncated

	out := ReadOutput{
		Content:       result,
		Encoding:      encInfo.Charset,
		TotalLines:    totalLines,
		Hash:          fileHash,
		ReturnedLines: returnedLines,
		Truncated:     truncated,
		NextOffset:    nextOffset,
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
Image files (PNG, JPG, GIF, BMP, WebP, TIFF, ICO) are returned as ImageContent (base64).
SVG files are returned as text. Supports offset/limit for reading specific line ranges.
Text defaults to 400 lines and 32768 characters; use offset/limit to continue.
Every text result ends with total line count, truncation state, and next_offset when more is available.
Negative offset reads from end (e.g. offset=-5 reads last 5 lines).
Offset accepts integer, string range "100-200", or [start, end] array.
Accepts "path" as alias for "file_path". Relative paths use the configured workspace, MCP client root, or server CWD in that order.`,
	}, Handle)
}

func handleImage(path string, fi os.FileInfo, mime string) (*mcp.CallToolResult, ReadOutput, error) {
	if fi.Size() > maxImageSize {
		return errorResult(fmt.Sprintf("image too large (%d bytes, max %d). Use download or compress first", fi.Size(), maxImageSize))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to read image: %v", err))
	}
	// SVG is text-based, return as text instead of binary image
	if mime == "image/svg+xml" {
		text := string(data)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: text}},
		}, ReadOutput{Content: text, Encoding: "utf-8", TotalLines: common.TextLineCount(text)}, nil
	}
	msg := fmt.Sprintf("Image: %s (%d bytes)", filepath.Base(path), fi.Size())
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.ImageContent{Data: data, MIMEType: mime},
			&mcp.TextContent{Text: msg},
		},
	}, ReadOutput{Content: msg, Encoding: "binary"}, nil
}

func errorResult(msg string) (*mcp.CallToolResult, ReadOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, ReadOutput{}, nil
}
