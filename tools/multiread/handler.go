package multiread

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
const readHashThreshold = 10 * 1024 * 1024 // 10MB

// maxFiles prevents abuse by limiting the number of files per request.
const maxFiles = 50

// maxTotalBytes caps total memory consumption across all files in a single request.
const maxTotalBytes int64 = 100 * 1024 * 1024 // 100MB

// fileEntry holds per-file read parameters resolved from input.
type fileEntry struct {
	Path          string
	Offset        int
	Limit         int
	LimitProvided bool
}

// FileRange specifies per-file read range. Used in the "files" parameter.
type FileRange struct {
	Path   string `json:"path" jsonschema:"Absolute or workspace-relative file path"`
	Offset *int   `json:"offset,omitempty" jsonschema:"Line offset (1-based, negative = from end). Default: 1"`
	Limit  *int   `json:"limit,omitempty" jsonschema:"Max lines to read. Default: 200. Set 0 to remove the line limit"`
}

type MultiReadInput struct {
	// Simple mode: list of paths, all using the same offset/limit.
	// Both "file_paths" and "paths" are accepted (alias for compatibility).
	FilePaths      []string `json:"file_paths,omitempty" jsonschema:"File paths to read. All files use the global offset/limit. Use files for per-file ranges"`
	Paths          []string `json:"paths,omitempty" jsonschema:"Compatibility alias for file_paths; prefer file_paths"`
	Offset         *int     `json:"offset,omitempty" jsonschema:"Line number to start from (1-based, negative = from end). Default: 1"`
	Limit          *int     `json:"limit,omitempty" jsonschema:"Maximum lines per file. Default: 200. Set 0 or all=true to remove the line limit"`
	All            bool     `json:"all,omitempty" jsonschema:"Remove the default per-file line limit. The total character budget still applies. Default: false"`
	MaxOutputChars int      `json:"max_output_chars,omitempty" jsonschema:"Maximum total returned text characters across all files. Default: 32768, Max: 131072"`
	MaxLineChars   int      `json:"max_line_chars,omitempty" jsonschema:"Maximum characters returned from one line. Default: 4000, Max: 32768"`
	IncludeHash    bool     `json:"include_hash,omitempty" jsonschema:"Include per-file SHA-256 hashes. Default: false"`

	// Advanced mode: per-file offset/limit. Takes priority over file_paths if both are provided
	Files []FileRange `json:"files,omitempty" jsonschema:"Per-file read ranges. Each entry has path, offset, limit. Takes priority over file_paths"`
}

// resolveEntries converts input to a unified list of fileEntry.
// Returns entries and a validation error string (non-empty means invalid input).
func resolveEntries(input MultiReadInput) ([]fileEntry, string) {
	globalOffset := 0
	if input.Offset != nil {
		globalOffset = *input.Offset
	}
	globalLimit := 0
	globalLimitProvided := input.Limit != nil
	if globalLimitProvided {
		globalLimit = *input.Limit
		if globalLimit < 0 {
			return nil, "limit must be non-negative"
		}
	} else if !input.All {
		globalLimit = 200
	}

	// Merge "paths" alias into file_paths
	if len(input.Paths) > 0 && len(input.FilePaths) == 0 {
		input.FilePaths = input.Paths
	}

	// "files" takes priority
	if len(input.Files) > 0 {
		entries := make([]fileEntry, len(input.Files))
		for i, f := range input.Files {
			off := globalOffset
			if f.Offset != nil {
				off = *f.Offset
			}
			lim := globalLimit
			provided := globalLimitProvided
			if f.Limit != nil {
				lim = *f.Limit
				provided = true
				if lim < 0 {
					return nil, fmt.Sprintf("files[%d].limit must be non-negative", i)
				}
			}
			entries[i] = fileEntry{Path: f.Path, Offset: off, Limit: lim, LimitProvided: provided}
		}
		return entries, ""
	}
	// Fallback to file_paths with global offset/limit
	entries := make([]fileEntry, len(input.FilePaths))
	for i, p := range input.FilePaths {
		entries[i] = fileEntry{Path: p, Offset: globalOffset, Limit: globalLimit, LimitProvided: globalLimitProvided}
	}
	return entries, ""
}

type MultiReadOutput struct {
	Content       string `json:"content"`
	FilesRead     int    `json:"files_read"`
	ErrorCount    int    `json:"error_count"`
	Truncated     bool   `json:"truncated"`
	NextFileIndex int    `json:"next_file_index,omitempty"`
	NextOffset    int    `json:"next_offset,omitempty"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input MultiReadInput) (*mcp.CallToolResult, MultiReadOutput, error) {
	entries, validErr := resolveEntries(input)
	if validErr != "" {
		return errorResult(validErr)
	}
	if len(entries) == 0 {
		return errorResult("file_paths is required and must not be empty")
	}
	if len(entries) > maxFiles {
		return errorResult(fmt.Sprintf("too many files: %d (maximum %d)", len(entries), maxFiles))
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
		maxLineChars = 4000
	}
	if maxLineChars > common.DefaultOutputChars {
		return errorResult(fmt.Sprintf("max_line_chars must be at most %d", common.DefaultOutputChars))
	}

	var sb strings.Builder
	var errorCount int
	var totalBytesRead int64
	filesRead := 0
	usedChars := 0
	contentBudget := maxOutputChars - 768
	if contentBudget < 256 {
		contentBudget = maxOutputChars
	}
	truncated := false
	nextFileIndex := 0
	nextOffset := 0

readLoop:
	for i, entry := range entries {
		filePath := entry.Path
		if i > 0 && !common.AppendWithinRuneBudget(&sb, &usedChars, "\n", contentBudget) {
			truncated = true
			nextFileIndex = i + 1
			break
		}

		if filePath == "" {
			common.AppendWithinRuneBudget(&sb, &usedChars, "=== (empty path) ===\nERROR: empty file path\n", contentBudget)
			errorCount++
			continue
		}

		resolvedPath, resolveErr := common.ResolveRequestPath(ctx, req, filePath)
		if resolveErr != nil {
			common.AppendWithinRuneBudget(&sb, &usedChars, fmt.Sprintf("=== %s ===\nERROR: cannot resolve path: %v\n", filePath, resolveErr), contentBudget)
			errorCount++
			continue
		}
		filePath = resolvedPath

		// Header for each file
		if !common.AppendWithinRuneBudget(&sb, &usedChars, fmt.Sprintf("=== %s (%s) ===\n", filepath.Base(filePath), filePath), contentBudget) {
			truncated = true
			nextFileIndex = i + 1
			break
		}

		fi, err := os.Stat(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				common.AppendWithinRuneBudget(&sb, &usedChars, fmt.Sprintf("ERROR: file not found: %s\n", filePath), contentBudget)
			} else {
				common.AppendWithinRuneBudget(&sb, &usedChars, fmt.Sprintf("ERROR: cannot access file: %v\n", err), contentBudget)
			}
			errorCount++
			continue
		}
		if fi.IsDir() {
			common.AppendWithinRuneBudget(&sb, &usedChars, fmt.Sprintf("ERROR: path is a directory, not a file: %s\n", filePath), contentBudget)
			errorCount++
			continue
		}

		// Check total memory budget before reading
		totalBytesRead += fi.Size()
		if totalBytesRead > maxTotalBytes {
			common.AppendWithinRuneBudget(&sb, &usedChars, "ERROR: total size limit exceeded (100MB), skipping remaining files\n", contentBudget)
			errorCount++
			truncated = true
			nextFileIndex = i + 1
			break
		}

		// .editorconfig charset hint
		hintCharset := edit.FindEditorConfigCharset(filePath)

		// Read with encoding detection
		content, encInfo, err := common.ReadFileWithEncoding(filePath, hintCharset)
		if err != nil {
			common.AppendWithinRuneBudget(&sb, &usedChars, fmt.Sprintf("ERROR: failed to read file: %v\n", err), contentBudget)
			errorCount++
			continue
		}
		filesRead++

		// Match bufio.ScanLines semantics; do not report a phantom line after a
		// final newline.
		totalLines := common.TextLineCount(content)

		// Calculate offset range using per-file values
		var startIdx, endIdx int
		if totalLines == 0 {
			startIdx = 0
		} else if entry.Offset < 0 {
			startIdx = totalLines + entry.Offset
			if startIdx < 0 {
				startIdx = 0
			}
		} else {
			offset := entry.Offset
			if offset < 1 {
				offset = 1
			}
			if offset > totalLines {
				offset = totalLines
			}
			startIdx = offset - 1
		}

		endIdx = totalLines
		if entry.Limit > 0 && startIdx+entry.Limit < endIdx {
			endIdx = startIdx + entry.Limit
		}

		// Format with line numbers
		scanner := bufio.NewScanner(strings.NewReader(content))
		scanner.Buffer(make([]byte, 64*1024), len(content)+1)
		lineNum := 0
		returnedLines := 0
		lineTruncated := false
		for scanner.Scan() {
			if lineNum >= endIdx {
				break
			}
			if lineNum >= startIdx {
				lineText, wasTruncated := common.TruncateRunes(scanner.Text(), maxLineChars, "… [line truncated]")
				lineTruncated = lineTruncated || wasTruncated
				formatted := fmt.Sprintf("%6d\t%s\n", lineNum+1, lineText)
				if !common.AppendWithinRuneBudget(&sb, &usedChars, formatted, contentBudget) {
					truncated = true
					nextFileIndex = i + 1
					nextOffset = lineNum + 1
					break readLoop
				}
				returnedLines++
			}
			lineNum++
		}
		if err := scanner.Err(); err != nil {
			common.AppendWithinRuneBudget(&sb, &usedChars, fmt.Sprintf("ERROR: scanner failed: %v\n", err), contentBudget)
			errorCount++
			continue
		}

		// Encoding warning
		if warning := common.EncodingWarning(encInfo); warning != "" {
			common.AppendWithinRuneBudget(&sb, &usedChars, warning, contentBudget)
		}

		// File hash (only for files <= 10MB)
		fileHash := ""
		if input.IncludeHash && fi.Size() <= readHashThreshold {
			if h, err := common.ComputeFileHash(filePath); err == nil {
				fileHash = h
			}
		}

		fileTruncated := endIdx < totalLines || lineTruncated
		truncated = truncated || fileTruncated
		firstLine, lastLine := startIdx+1, startIdx+returnedLines
		if returnedLines == 0 {
			firstLine, lastLine = 0, 0
		}
		footer := fmt.Sprintf("[file: lines=%d-%d/%d; returned=%d; truncated=%t; encoding=%s",
			firstLine, lastLine, totalLines, returnedLines, fileTruncated, encInfo.Charset)
		if endIdx < totalLines {
			footer += fmt.Sprintf("; next_offset=%d", endIdx+1)
		}
		if lineTruncated {
			footer += "; line_truncated=true"
		}
		if fileHash != "" {
			footer += "; sha256=" + fileHash
		}
		footer += "]\n"
		if !common.AppendWithinRuneBudget(&sb, &usedChars, footer, contentBudget) {
			truncated = true
			nextFileIndex = i + 1
			nextOffset = endIdx + 1
			break
		}
	}

	summary := fmt.Sprintf("\n[multiread: files_read=%d/%d; errors=%d; truncated=%t", filesRead, len(entries), errorCount, truncated)
	if nextFileIndex > 0 {
		summary += fmt.Sprintf("; next_file_index=%d", nextFileIndex)
	}
	if nextOffset > 0 {
		summary += fmt.Sprintf("; next_offset=%d", nextOffset)
	}
	summary += "]"
	sb.WriteString(summary)

	result, finalTruncated := common.TruncateRunes(sb.String(), maxOutputChars, "\n[truncated=true; retry with the remaining file_paths and next_offset from the previous footer]")
	truncated = truncated || finalTruncated

	return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: result}},
		}, MultiReadOutput{
			Content:       result,
			FilesRead:     filesRead,
			ErrorCount:    errorCount,
			Truncated:     truncated,
			NextFileIndex: nextFileIndex,
			NextOffset:    nextOffset,
		}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "multiread",
		Description: `Reads multiple files in a single call to reduce API round-trips.
Encoding-aware: auto-detects file encoding for each file.
Supports offset/limit for reading specific line ranges.
Defaults to 200 lines per file and 32768 characters total across the call.
Returns visible per-file and overall truncation metadata with continuation positions.
Use file_paths or paths (string array) with global offset/limit, or files (object array) for per-file offset/limit.
If a file fails, the error is included in output and remaining files continue.
Maximum 50 files per request.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, MultiReadOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, MultiReadOutput{}, nil
}
