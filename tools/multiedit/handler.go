package multiedit

import (
	"context"
	"fmt"
	"os"
	"strings"

	"agent-tool/common"
	"agent-tool/internal/textdiff"
	"agent-tool/tools/edit"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// EditOp is a single old_string -> new_string replacement within a multiedit call.
type EditOp struct {
	OldString  string      `json:"old_string" jsonschema:"Exact text to find"`
	NewString  string      `json:"new_string" jsonschema:"Replacement text"`
	ReplaceAll interface{} `json:"replace_all,omitempty" jsonschema:"Replace all occurrences instead of just the first: true or false. Default: false"`
}

// MultiEditInput is the input for the multiedit tool.
type MultiEditInput struct {
	FilePath string      `json:"file_path,omitempty" jsonschema:"File to edit. Relative paths use the configured workspace or MCP client root"`
	Path     string      `json:"path,omitempty" jsonschema:"Alias for file_path"`
	Edits    []EditOp    `json:"edits" jsonschema:"Ordered list of replacements to apply sequentially"`
	DryRun   interface{} `json:"dry_run,omitempty" jsonschema:"Preview changes without modifying the file: true or false. Default: false"`
}

// MultiEditOutput is the output of the multiedit tool.
type MultiEditOutput struct {
	Result string `json:"result"`
}

// Handle is the MCP handler for the multiedit tool.
func Handle(ctx context.Context, req *mcp.CallToolRequest, input MultiEditInput) (*mcp.CallToolResult, MultiEditOutput, error) {
	if input.FilePath == "" {
		input.FilePath = input.Path
	}
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	resolvedPath, err := common.ResolveRequestPath(ctx, req, input.FilePath)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot resolve file_path: %v", err))
	}
	input.FilePath = resolvedPath
	if len(input.Edits) == 0 {
		return errorResult("edits is required and must have at least one entry")
	}

	// Validate all edits before touching the file
	for i, op := range input.Edits {
		if op.OldString == "" {
			return errorResult(fmt.Sprintf("edits[%d]: old_string is required", i))
		}
		if op.OldString == op.NewString {
			return errorResult(fmt.Sprintf("edits[%d]: old_string and new_string must be different", i))
		}
	}

	if _, err := os.Stat(input.FilePath); err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("file not found: %s", input.FilePath))
		}
		return errorResult(fmt.Sprintf("cannot access file: %v", err))
	}

	hintCharset := edit.FindEditorConfigCharset(input.FilePath)
	content, encInfo, err := common.ReadFileWithEncoding(input.FilePath, hintCharset)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to read file: %v", err))
	}

	fileStyle := edit.DetectIndent(input.FilePath, content)

	// Apply edits sequentially; abort on first failure (atomic -- nothing written yet)
	current := content
	var messages []string
	for i, op := range input.Edits {
		result := edit.Replace(current, op.OldString, op.NewString, common.FlexBool(op.ReplaceAll), fileStyle, false)
		if !result.Applied {
			return errorResult(fmt.Sprintf("edits[%d]: %s", i, result.Message))
		}
		current = result.Content
		messages = append(messages, fmt.Sprintf("[%d] %s", i, result.Message))
	}

	summary := strings.Join(messages, "\n")

	if common.FlexBool(input.DryRun) {
		preview := dryRunPreview(content, current, input.FilePath)
		msg := fmt.Sprintf("[DRY RUN] %s (%s, encoding=%s)\n\n%s", summary, input.FilePath, encInfo.Charset, preview)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, MultiEditOutput{Result: msg}, nil
	}

	if err := common.WriteFileWithEncoding(input.FilePath, current, encInfo); err != nil {
		return errorResult(fmt.Sprintf("failed to write file: %v", err))
	}

	msg := fmt.Sprintf("OK: applied %d edit(s) to %s (encoding=%s)\n%s", len(input.Edits), input.FilePath, encInfo.Charset, summary)

	// One echo for the whole call: a per-edit header would repeat for every
	// entry, and what matters is the set of characters written. Newline-joined
	// so a line break ends each run and two edits never merge into one phrase.
	var written strings.Builder
	for _, e := range input.Edits {
		written.WriteString(e.NewString)
		written.WriteString("\n")
	}
	if echo := common.NonASCIIEcho(written.String()); echo != "" {
		msg += "\nnon-ASCII written: " + echo
	}
	if notice := common.InvisibleCharNotice(written.String()); notice != "" {
		msg += "\n" + notice
	}

	// U+FFFD is located per edit, not against the concatenation above: a line
	// number counted through the join points at neither the file nor the edit.
	for i, e := range input.Edits {
		if count, _ := common.ReplacementCharCount(e.NewString); count > 0 {
			msg += fmt.Sprintf("\n%s %d replacement char(s) U+FFFD in edits[%d].new_string. "+
				"These were corrupted before reaching this tool and the original characters "+
				"cannot be recovered -- re-send that text.", common.WarnSign, count, i)
		}
	}

	if warning := common.EncodingWarning(encInfo); warning != "" {
		msg += warning
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, MultiEditOutput{Result: msg}, nil
}

// Register registers the multiedit tool with the MCP server.
func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "multiedit",
		Description: `Applies multiple old_string -> new_string replacements to a single file in one call.
Edits are applied sequentially in order; each edit sees the result of the previous one.
Atomic: if any edit fails, the file is not modified at all.
Encoding-aware: preserves original file encoding (UTF-8, EUC-KR, Shift-JIS, etc.).
Line-ending aware: old_string matches whether the file uses CRLF or LF, and inserted newlines follow the region being edited (mixed-newline files stay intact).
Accepts "path" as alias for "file_path".
Use dry_run=true to preview all changes without modifying the file.`,
	}, Handle)
}

// dryRunPreview produces an accurate unified diff between before and after.
func dryRunPreview(before, after, filePath string) string {
	return textdiff.UnifiedStrings(filePath+" (before)", filePath+" (after)", before, after, 3)
}

func errorResult(msg string) (*mcp.CallToolResult, MultiEditOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, MultiEditOutput{}, nil
}
