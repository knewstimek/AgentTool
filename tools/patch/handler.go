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
	FilePath string `json:"file_path,omitempty" jsonschema:"Absolute path to the file to patch"`
	Path     string `json:"path,omitempty" jsonschema:"Alias for file_path"`
	Patch    string `json:"patch" jsonschema:"Unified diff text (output of the diff tool)"`
	DryRun   interface{} `json:"dry_run,omitempty" jsonschema:"Preview patch result without modifying the file: true or false. Default: false"`
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
		input.FilePath = input.Path
	}
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

	// Each line keeps the exact bytes that terminated it instead of the file
	// being normalized to one form and rebuilt. A file mixing CRLF and LF -- a
	// CRLF-era file with later LF-only edits -- would otherwise have every line
	// outside the hunks silently rewritten.
	lines := splitKeepingTerminators(content)
	origLineCount := len(lines)
	dominant := common.DetectLineEnding(content)
	endsWithNewline := strings.HasSuffix(content, "\n") || content == ""

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
				if hl.text != lines[srcIdx].text {
					return errorResult(fmt.Sprintf("hunk %d: context mismatch at line %d:\n  expected: %q\n  actual:   %q", i+1, srcIdx+1, hl.text, lines[srcIdx]))
				}
				srcIdx++
				srcConsumed++
			}
		}

		// Apply substitution. A line the patch introduces takes the ending of
		// the line it replaces, falling back to the line it will precede and
		// then to the file's dominant form -- never a file-wide rewrite.
		var newLines []srcLine
		srcIdx = startIdx
		replacedTerm := ""
		for _, hl := range h.lines {
			switch hl.op {
			case ' ':
				if srcIdx >= len(lines) {
					return errorResult(fmt.Sprintf("hunk %d: index out of range at line %d during apply", i+1, srcIdx+1))
				}
				newLines = append(newLines, lines[srcIdx])
				srcIdx++
				replacedTerm = ""
			case '-':
				if srcIdx >= len(lines) {
					return errorResult(fmt.Sprintf("hunk %d: index out of range at line %d during apply", i+1, srcIdx+1))
				}
				replacedTerm = lines[srcIdx].term
				srcIdx++ // delete -- skip
			case '+':
				term := replacedTerm
				if term == "" && srcIdx < len(lines) {
					term = lines[srcIdx].term
				}
				if term == "" && srcIdx > 0 {
					term = lines[srcIdx-1].term
				}
				if term == "" {
					term = dominant
				}
				newLines = append(newLines, srcLine{text: hl.text, term: term})
			}
		}

		// Replace lines (using actual consumed line count, not the header's srcCount)
		result := make([]srcLine, 0, len(lines)-srcConsumed+len(newLines))
		result = append(result, lines[:startIdx]...)
		result = append(result, newLines...)
		result = append(result, lines[startIdx+srcConsumed:]...)
		lines = result
	}

	// Combine result, each line with the ending it came in with. Whether the
	// file ends with a newline is a property of the original and is preserved:
	// the old code appended one unconditionally.
	var sb strings.Builder
	sb.Grow(len(content))
	for i, l := range lines {
		sb.WriteString(l.text)
		last := i == len(lines)-1
		switch {
		case last && !endsWithNewline:
		case l.term != "":
			sb.WriteString(l.term)
		default:
			// An unterminated line that is no longer last would otherwise
			// swallow the line now following it.
			sb.WriteString(dominant)
		}
	}
	output := sb.String()

	if common.FlexBool(input.DryRun) {
		// Calculate line count change
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

	// Only the added lines are new text; the rest of the diff is context that
	// already exists in the file and would be noise to echo back.
	msg += common.TextGuardNotice(addedLines(input.Patch))

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, PatchOutput{Result: msg}, nil
}

// srcLine is one line of the file plus the exact bytes that terminated it. The
// last line carries an empty terminator when the file does not end with one.
type srcLine struct {
	text string
	term string
}

// splitKeepingTerminators splits on LF while recording each line's own ending,
// so lines outside the patched hunks are written back byte-identical.
func splitKeepingTerminators(content string) []srcLine {
	var out []srcLine
	start := 0
	for i := 0; i < len(content); i++ {
		if content[i] != '\n' {
			continue
		}
		text, term := content[start:i], "\n"
		if i > start && content[i-1] == '\r' {
			text, term = content[start:i-1], "\r\n"
		}
		out = append(out, srcLine{text: text, term: term})
		start = i + 1
	}
	if start < len(content) {
		out = append(out, srcLine{text: content[start:]})
	}
	return out
}

// addedLines extracts the "+" lines of a unified diff -- the text the patch
// introduces. Hunk headers ("+++") are excluded.
func addedLines(patch string) string {
	var sb strings.Builder
	for _, line := range strings.Split(patch, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			sb.WriteString(line[1:])
			sb.WriteString("\n")
		}
	}
	return sb.String()
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
