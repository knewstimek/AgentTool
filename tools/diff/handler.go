package diff

import (
	"context"
	"fmt"
	"strings"

	"agent-tool/common"
	"agent-tool/internal/textdiff"
	"agent-tool/tools/edit"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maxDiffLines = 50000

type DiffInput struct {
	FileA string `json:"file_a,omitempty" jsonschema:"First file. Relative paths use workspace/MCP root"`
	FileB string `json:"file_b,omitempty" jsonschema:"Second file. Relative paths use workspace/MCP root"`
	// Aliases for compatibility
	PathA          string `json:"path_a,omitempty" jsonschema:"Alias for file_a"`
	PathB          string `json:"path_b,omitempty" jsonschema:"Alias for file_b"`
	ContextLines   int    `json:"context_lines,omitempty" jsonschema:"Number of context lines around changes. Default: 3, Max: 1000"`
	MaxOutputChars int    `json:"max_output_chars,omitempty" jsonschema:"Maximum returned diff characters. Default: 32768, Max: 131072"`
}

type DiffOutput struct {
	Result    string `json:"result"`
	Truncated bool   `json:"truncated"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input DiffInput) (*mcp.CallToolResult, DiffOutput, error) {
	// Merge path_a/path_b aliases
	if input.FileA == "" && input.PathA != "" {
		input.FileA = input.PathA
	}
	if input.FileB == "" && input.PathB != "" {
		input.FileB = input.PathB
	}

	if input.FileA == "" || input.FileB == "" {
		return errorResult("file_a and file_b are required")
	}
	var err error
	input.FileA, err = common.ResolveRequestPath(ctx, req, input.FileA)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot resolve file_a: %v", err))
	}
	input.FileB, err = common.ResolveRequestPath(ctx, req, input.FileB)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot resolve file_b: %v", err))
	}
	ctxLines := input.ContextLines
	if ctxLines <= 0 {
		ctxLines = 3
	}
	if ctxLines > 1000 {
		return errorResult("context_lines must be at most 1000")
	}
	maxOutputChars := input.MaxOutputChars
	if maxOutputChars <= 0 {
		maxOutputChars = common.DefaultOutputChars
	}
	if maxOutputChars > common.HardOutputChars {
		return errorResult(fmt.Sprintf("max_output_chars must be at most %d", common.HardOutputChars))
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

	linesA := textdiff.SplitLines(contentA)
	linesB := textdiff.SplitLines(contentB)

	if len(linesA) > maxDiffLines || len(linesB) > maxDiffLines {
		return errorResult(fmt.Sprintf("files too large for diff (max %d lines each)", maxDiffLines))
	}

	if contentA == contentB {
		msg := "Files are identical"
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, DiffOutput{Result: msg}, nil
	}

	diff := textdiff.Unified(input.FileA, input.FileB, linesA, linesB, ctxLines)

	// Lines are compared with their endings normalized, so files differing only
	// in terminator bytes produce an empty diff. Saying so beats handing back a
	// header with no hunks and letting the caller conclude nothing differs.
	if !strings.Contains(diff, "@@") {
		infoA := common.AnalyzeLineEndings(contentA)
		infoB := common.AnalyzeLineEndings(contentB)
		var notes []string

		// Kept separate from the newline form: this is what GNU diff prints as
		// "\ No newline at end of file", and calling it a line-ending
		// difference would point the caller at the wrong thing.
		endsA := strings.HasSuffix(contentA, "\n")
		endsB := strings.HasSuffix(contentB, "\n")
		if endsA != endsB {
			missing := "file_b"
			if !endsA {
				missing = "file_a"
			}
			notes = append(notes, missing+" has no newline at end of file")
		}
		// Only meaningful when both files have newlines at all: a file with
		// none differs by the missing terminator above, not by its form.
		bothHaveNewlines := infoA.CRLFCount+infoA.LFCount+infoA.CRCount > 0 &&
			infoB.CRLFCount+infoB.LFCount+infoB.CRCount > 0
		if bothHaveNewlines && (infoA.Kind != infoB.Kind ||
			infoA.CRLFCount != infoB.CRLFCount || infoA.LFCount != infoB.LFCount || infoA.CRCount != infoB.CRCount) {
			notes = append(notes, fmt.Sprintf("line endings differ: file_a=%s (CRLF %d, LF %d, CR %d), file_b=%s (CRLF %d, LF %d, CR %d)",
				infoA.Kind, infoA.CRLFCount, infoA.LFCount, infoA.CRCount,
				infoB.Kind, infoB.CRLFCount, infoB.LFCount, infoB.CRCount))
		}
		if len(notes) == 0 {
			notes = append(notes, "the files differ only in bytes that do not form lines")
		}
		diff += "\n(no content difference; " + strings.Join(notes, "; ") + ")"
	}

	diff, truncated := common.TruncateRunes(diff, maxOutputChars,
		"\n[truncated=true; reduce context_lines or compare a narrower extracted region]")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: diff}},
	}, DiffOutput{Result: diff, Truncated: truncated}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "diff",
		Description: `Compares two files and outputs a unified diff.
Encoding-aware: auto-detects file encoding before comparison.
Lines are compared with their endings normalized; files differing only in line endings or a trailing newline say so explicitly instead of returning an empty diff.
Max 50,000 lines per file. Output defaults to 32768 characters and visibly reports truncation.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, DiffOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, DiffOutput{Result: msg}, nil
}
