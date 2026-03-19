package patch

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"agent-tool/common"
	"agent-tool/tools/edit"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// maxPatchSize is the maximum size of patch text (to prevent OOM).
const maxPatchSize = 10 * 1024 * 1024 // 10MB

type PatchInput struct {
	FilePath string `json:"file_path" jsonschema:"Absolute path to the file to patch"`
	Patch    string `json:"patch" jsonschema:"Unified diff text (output of the diff tool)"`
	DryRun   bool   `json:"dry_run,omitempty" jsonschema:"Preview patch result without modifying the file (default false)"`
}

type PatchOutput struct {
	Result string `json:"result"`
}

var reHunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

type hunk struct {
	srcStart int // 1-based
	srcCount int
	dstStart int
	dstCount int
	lines    []hunkLine
}

type hunkLine struct {
	op   byte // ' ', '-', '+'
	text string
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input PatchInput) (*mcp.CallToolResult, PatchOutput, error) {
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	if !filepath.IsAbs(input.FilePath) {
		return errorResult("file_path must be an absolute path")
	}
	if input.Patch == "" {
		return errorResult("patch is required")
	}

	// Limit patch text size (to prevent OOM)
	if len(input.Patch) > maxPatchSize {
		return errorResult(fmt.Sprintf("patch too large (%d bytes, max %d bytes)", len(input.Patch), maxPatchSize))
	}

	// Parse the patch
	hunks, err := parseUnifiedDiff(input.Patch)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to parse patch: %v", err))
	}
	if len(hunks) == 0 {
		return errorResult("no hunks found in patch")
	}

	// Read file (encoding-aware)
	hintCharset := edit.FindEditorConfigCharset(input.FilePath)
	content, encInfo, err := common.ReadFileWithEncoding(input.FilePath, hintCharset)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to read file: %v", err))
	}

	// Normalize CRLF to LF
	lineEnding := "\n"
	if strings.Contains(content, "\r\n") {
		lineEnding = "\r\n"
		content = strings.ReplaceAll(content, "\r\n", "\n")
	}

	// Split into lines
	lines := strings.Split(content, "\n")
	// Handle trailing empty line
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	// Apply hunks in reverse order — applying from the end prevents line number shifts
	for i := len(hunks) - 1; i >= 0; i-- {
		h := hunks[i]
		startIdx := h.srcStart - 1 // 0-based

		// Validate startIdx
		if startIdx < 0 {
			return errorResult(fmt.Sprintf("hunk %d: invalid source start line %d", i+1, h.srcStart))
		}
		if startIdx > len(lines) {
			return errorResult(fmt.Sprintf("hunk %d: source start line %d exceeds file length %d", i+1, h.srcStart, len(lines)))
		}

		// Verify context lines + count actual source lines consumed
		srcIdx := startIdx
		srcConsumed := 0
		for _, hl := range h.lines {
			if hl.op == ' ' || hl.op == '-' {
				if srcIdx >= len(lines) {
					return errorResult(fmt.Sprintf("hunk %d: context mismatch at line %d (file has only %d lines)", i+1, srcIdx+1, len(lines)))
				}
				if hl.text != lines[srcIdx] {
					return errorResult(fmt.Sprintf("hunk %d: context mismatch at line %d:\n  expected: %q\n  actual:   %q", i+1, srcIdx+1, hl.text, lines[srcIdx]))
				}
				srcIdx++
				srcConsumed++
			}
		}

		// Apply substitution
		var newLines []string
		srcIdx = startIdx
		for _, hl := range h.lines {
			switch hl.op {
			case ' ':
				if srcIdx >= len(lines) {
					return errorResult(fmt.Sprintf("hunk %d: index out of range at line %d during apply", i+1, srcIdx+1))
				}
				newLines = append(newLines, lines[srcIdx])
				srcIdx++
			case '-':
				if srcIdx >= len(lines) {
					return errorResult(fmt.Sprintf("hunk %d: index out of range at line %d during apply", i+1, srcIdx+1))
				}
				srcIdx++ // delete — skip
			case '+':
				newLines = append(newLines, hl.text)
			}
		}

		// Replace lines (using actual consumed line count, not the header's srcCount)
		result := make([]string, 0, len(lines)-srcConsumed+len(newLines))
		result = append(result, lines[:startIdx]...)
		result = append(result, newLines...)
		result = append(result, lines[startIdx+srcConsumed:]...)
		lines = result
	}

	// Combine result
	output := strings.Join(lines, "\n")
	if output != "" {
		output += "\n" // restore trailing newline
	}

	// Restore original line endings
	if lineEnding == "\r\n" {
		output = strings.ReplaceAll(output, "\n", "\r\n")
	}

	if input.DryRun {
		// Calculate line count change
		origLineCount := len(strings.Split(content, "\n"))
		newLineCount := len(lines)
		delta := newLineCount - origLineCount
		sign := "+"
		if delta < 0 {
			sign = ""
		}
		msg := fmt.Sprintf("[DRY RUN] patch would apply %d hunk(s) to %s (lines: %d → %d, %s%d)",
			len(hunks), input.FilePath, origLineCount, newLineCount, sign, delta)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, PatchOutput{Result: msg}, nil
	}

	// Write file (preserving encoding)
	if err := common.WriteFileWithEncoding(input.FilePath, output, encInfo); err != nil {
		return errorResult(fmt.Sprintf("failed to write file: %v", err))
	}

	msg := fmt.Sprintf("OK: applied %d hunk(s) to %s (encoding=%s)", len(hunks), input.FilePath, encInfo.Charset)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, PatchOutput{Result: msg}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "patch",
		Description: `Applies a unified diff patch to a file.
Parses @@ hunk headers, verifies context lines, and applies changes.
Encoding-aware: preserves original file encoding.
Use dry_run=true to preview without modifying the file.`,
	}, Handle)
}

// parseUnifiedDiff extracts hunks from a unified diff string.
func parseUnifiedDiff(patch string) ([]hunk, error) {
	// Normalize CRLF
	patch = strings.ReplaceAll(patch, "\r\n", "\n")
	// Remove trailing newlines
	patch = strings.TrimRight(patch, "\n")
	lines := strings.Split(patch, "\n")

	var hunks []hunk
	var current *hunk

	for _, line := range lines {
		// Skip --- / +++ headers
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") {
			continue
		}

		if m := reHunkHeader.FindStringSubmatch(line); m != nil {
			srcStart, err := strconv.Atoi(m[1])
			if err != nil || srcStart < 0 {
				return nil, fmt.Errorf("invalid hunk srcStart: %q", m[1])
			}
			srcCount := 1
			if m[2] != "" {
				srcCount, err = strconv.Atoi(m[2])
				if err != nil || srcCount < 0 {
					return nil, fmt.Errorf("invalid hunk srcCount: %q", m[2])
				}
			}
			dstStart, err := strconv.Atoi(m[3])
			if err != nil || dstStart < 0 {
				return nil, fmt.Errorf("invalid hunk dstStart: %q", m[3])
			}
			dstCount := 1
			if m[4] != "" {
				dstCount, err = strconv.Atoi(m[4])
				if err != nil || dstCount < 0 {
					return nil, fmt.Errorf("invalid hunk dstCount: %q", m[4])
				}
			}

			hunks = append(hunks, hunk{
				srcStart: srcStart,
				srcCount: srcCount,
				dstStart: dstStart,
				dstCount: dstCount,
			})
			current = &hunks[len(hunks)-1]
			continue
		}

		if current == nil {
			continue
		}

		if len(line) == 0 {
			// Treat empty lines as context lines (in real diffs, empty context lines have no " " prefix)
			current.lines = append(current.lines, hunkLine{op: ' ', text: ""})
			continue
		}

		op := line[0]
		text := line[1:]
		switch op {
		case ' ':
			current.lines = append(current.lines, hunkLine{op: ' ', text: text})
		case '-':
			current.lines = append(current.lines, hunkLine{op: '-', text: text})
		case '+':
			current.lines = append(current.lines, hunkLine{op: '+', text: text})
		case '\\':
			// "\ No newline at end of file" — ignore
		default:
			// Plain text outside a hunk — ignore
		}
	}

	return hunks, nil
}

func errorResult(msg string) (*mcp.CallToolResult, PatchOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, PatchOutput{Result: msg}, nil
}
