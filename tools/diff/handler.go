package diff

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"agent-tool/common"
	"agent-tool/tools/edit"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maxDiffLines = 50000

type DiffInput struct {
	FileA        string `json:"file_a" jsonschema:"Absolute path to the first file"`
	FileB        string `json:"file_b" jsonschema:"Absolute path to the second file"`
	ContextLines interface{} `json:"context_lines,omitempty" jsonschema:"Number of context lines around changes (default 3)"`
}

type DiffOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input DiffInput) (*mcp.CallToolResult, DiffOutput, error) {
	if input.FileA == "" || input.FileB == "" {
		return errorResult("file_a and file_b are required")
	}
	if !filepath.IsAbs(input.FileA) || !filepath.IsAbs(input.FileB) {
		return errorResult("file_a and file_b must be absolute paths")
	}
	ctxLines, ok := common.FlexInt(input.ContextLines)
	if !ok {
		return errorResult("context_lines must be an integer")
	}
	if ctxLines <= 0 {
		ctxLines = 3
	}

	// Encoding-aware reading
	hintA := edit.FindEditorConfigCharset(input.FileA)
	contentA, _, err := common.ReadFileWithEncoding(input.FileA, hintA)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to read file_a: %v", err))
	}

	hintB := edit.FindEditorConfigCharset(input.FileB)
	contentB, _, err := common.ReadFileWithEncoding(input.FileB, hintB)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to read file_b: %v", err))
	}

	linesA := splitLines(contentA)
	linesB := splitLines(contentB)

	if len(linesA) > maxDiffLines || len(linesB) > maxDiffLines {
		return errorResult(fmt.Sprintf("files too large for diff (max %d lines each)", maxDiffLines))
	}

	if contentA == contentB {
		msg := "Files are identical"
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, DiffOutput{Result: msg}, nil
	}

	diff := unifiedDiff(input.FileA, input.FileB, linesA, linesB, ctxLines)

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: diff}},
	}, DiffOutput{Result: diff}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "diff",
		Description: `Compares two files and outputs a unified diff.
Encoding-aware: auto-detects file encoding before comparison.
Max 50,000 lines per file.`,
	}, Handle)
}

// splitLines splits a string into lines. Returns nil for empty strings.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	// Normalize CRLF to LF
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	// Remove trailing empty line (from trailing newline)
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// --- LCS-based unified diff ---

// Uses a simple DP-based LCS instead of Myers algorithm.
// O(nm) memory, but practical with the maxDiffLines (50K lines) limit.
// Since 50K x 50K is too large, full LCS is only used for small files;
// large files use a line-hash based approximate diff.
func unifiedDiff(nameA, nameB string, a, b []string, ctxLines int) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("--- %s\n+++ %s\n", nameA, nameB))

	// Compute edit script
	edits := computeEdits(a, b)

	// Group into hunks
	hunks := groupHunks(edits, len(a), len(b), ctxLines)

	for _, hunk := range hunks {
		sb.WriteString(hunk)
	}

	return sb.String()
}

type editOp byte

const (
	opEqual  editOp = ' '
	opDelete editOp = '-'
	opInsert editOp = '+'
)

type editEntry struct {
	op   editOp
	line string
}

// computeEdits returns the edit script needed to transform a into b.
func computeEdits(a, b []string) []editEntry {
	return computeEditsWithDepth(a, b, 0)
}

const maxRecursionDepth = 5

func computeEditsWithDepth(a, b []string, depth int) []editEntry {
	n, m := len(a), len(b)

	// When recursion depth is exceeded, fall back to delete-all + insert-all
	if depth >= maxRecursionDepth {
		return bruteForceEdits(a, b)
	}

	// Large files: use line-hash based simplification
	if int64(n)*int64(m) > 10_000_000 {
		return computeEditsHashed(a, b, depth)
	}

	// Small files: standard LCS DP
	// dp[i][j] = LCS length of a[:i], b[:j]
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}

	// Backtrack
	var edits []editEntry
	i, j := n, m
	for i > 0 || j > 0 {
		if i > 0 && j > 0 && a[i-1] == b[j-1] {
			edits = append(edits, editEntry{opEqual, a[i-1]})
			i--
			j--
		} else if j > 0 && (i == 0 || dp[i][j-1] >= dp[i-1][j]) {
			edits = append(edits, editEntry{opInsert, b[j-1]})
			j--
		} else {
			edits = append(edits, editEntry{opDelete, a[i-1]})
			i--
		}
	}

	// Reverse to get correct order
	for left, right := 0, len(edits)-1; left < right; left, right = left+1, right-1 {
		edits[left], edits[right] = edits[right], edits[left]
	}

	return edits
}

// bruteForceEdits treats everything as delete + insert (used when recursion depth is exceeded).
func bruteForceEdits(a, b []string) []editEntry {
	var edits []editEntry
	for _, line := range a {
		edits = append(edits, editEntry{opDelete, line})
	}
	for _, line := range b {
		edits = append(edits, editEntry{opInsert, line})
	}
	return edits
}

// computeEditsHashed is a patience-like diff for large files.
// Hashes lines to match unique lines, then treats the rest as insert/delete.
func computeEditsHashed(a, b []string, depth int) []editEntry {
	// Simple approach: strip common prefix/suffix from both ends,
	// then treat the middle portion as delete-all + insert-all.
	prefixLen := 0
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for prefixLen < minLen && a[prefixLen] == b[prefixLen] {
		prefixLen++
	}

	suffixLen := 0
	for suffixLen < minLen-prefixLen && a[len(a)-1-suffixLen] == b[len(b)-1-suffixLen] {
		suffixLen++
	}

	var edits []editEntry

	// Common prefix
	for i := 0; i < prefixLen; i++ {
		edits = append(edits, editEntry{opEqual, a[i]})
	}

	// Guard suffixLen range
	if len(a)-suffixLen < prefixLen || len(b)-suffixLen < prefixLen {
		suffixLen = 0
	}

	// Middle differing portion
	midA := a[prefixLen : len(a)-suffixLen]
	midB := b[prefixLen : len(b)-suffixLen]

	// If the middle portion is small enough, retry with LCS (passing depth)
	if int64(len(midA))*int64(len(midB)) <= 10_000_000 {
		midEdits := computeEditsWithDepth(midA, midB, depth+1)
		edits = append(edits, midEdits...)
	} else {
		edits = append(edits, bruteForceEdits(midA, midB)...)
	}

	// Common suffix
	for i := len(a) - suffixLen; i < len(a); i++ {
		edits = append(edits, editEntry{opEqual, a[i]})
	}

	return edits
}

// groupHunks groups the edit script into unified diff hunks.
func groupHunks(edits []editEntry, lenA, lenB, ctxLines int) []string {
	// Collect change indices
	type change struct{ idx int }
	var changes []change
	for i, e := range edits {
		if e.op != opEqual {
			changes = append(changes, change{i})
		}
	}

	if len(changes) == 0 {
		return nil
	}

	// Group changes with context
	var hunks []string
	i := 0
	for i < len(changes) {
		// Start/end of group
		start := changes[i].idx - ctxLines
		if start < 0 {
			start = 0
		}

		end := changes[i].idx + ctxLines + 1
		if end > len(edits) {
			end = len(edits)
		}

		// Merge adjacent changes
		for i+1 < len(changes) && changes[i+1].idx-ctxLines <= end {
			i++
			end = changes[i].idx + ctxLines + 1
			if end > len(edits) {
				end = len(edits)
			}
		}

		// Compute hunk header
		aLine := 1 // 1-based
		bLine := 1
		for k := 0; k < start; k++ {
			switch edits[k].op {
			case opEqual:
				aLine++
				bLine++
			case opDelete:
				aLine++
			case opInsert:
				bLine++
			}
		}

		aCount := 0
		bCount := 0
		var body strings.Builder
		for k := start; k < end; k++ {
			e := edits[k]
			switch e.op {
			case opEqual:
				body.WriteString(" " + e.line + "\n")
				aCount++
				bCount++
			case opDelete:
				body.WriteString("-" + e.line + "\n")
				aCount++
			case opInsert:
				body.WriteString("+" + e.line + "\n")
				bCount++
			}
		}

		header := fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", aLine, aCount, bLine, bCount)
		hunks = append(hunks, header+body.String())

		i++
	}

	return hunks
}

func errorResult(msg string) (*mcp.CallToolResult, DiffOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, DiffOutput{Result: msg}, nil
}
