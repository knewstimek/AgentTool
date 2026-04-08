package edit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// EditInput is the input parameter for the Edit tool.
type EditInput struct {
	FilePath     string      `json:"file_path,omitempty" jsonschema:"Absolute path to the file to edit"`
	Path         string      `json:"path,omitempty" jsonschema:"Alias for file_path"`
	OldString    string      `json:"old_string,omitempty" jsonschema:"Exact text to find in the file"`
	NewString    string      `json:"new_string,omitempty" jsonschema:"Replacement text (must differ from old_string)"`
	OldContent   string      `json:"old_content,omitempty" jsonschema:"Alias for old_string"`
	NewContent   string      `json:"new_content,omitempty" jsonschema:"Alias for new_string"`
	ReplaceAll   interface{} `json:"replace_all,omitempty" jsonschema:"Replace all occurrences instead of just the first: true or false. Default: false"`
	DryRun       interface{} `json:"dry_run,omitempty" jsonschema:"Preview changes without modifying the file: true or false. Default: false"`
	IndentStyle  string      `json:"indent_style,omitempty" jsonschema:"Override indentation style. Values: tabs or spaces-N (e.g. spaces-4). Empty = auto-detect (default)"`
	ExpectedHash string      `json:"expected_hash,omitempty" jsonschema:"Optional SHA-256 hash of the file. If provided and mismatched, edit is rejected (optimistic concurrency)."`
}

// EditOutput is the output of the Edit tool.
type EditOutput struct {
	Result string `json:"result"`
}

// Handle is the MCP handler for the Edit tool.
func Handle(ctx context.Context, req *mcp.CallToolRequest, input EditInput) (*mcp.CallToolResult, EditOutput, error) {
	// Input validation
	if input.FilePath == "" {
		input.FilePath = input.Path
	}
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	if !filepath.IsAbs(input.FilePath) {
		return errorResult("file_path must be an absolute path")
	}
	// Accept old_content/new_content as aliases for old_string/new_string
	if input.OldString == "" && input.OldContent != "" {
		input.OldString = input.OldContent
	}
	if input.NewString == "" && input.NewContent != "" {
		input.NewString = input.NewContent
	}
	if input.OldString == "" {
		return errorResult("old_string is required")
	}
	if input.OldString == input.NewString {
		return errorResult("old_string and new_string must be different")
	}

	// Check file existence
	if _, err := os.Stat(input.FilePath); err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("file not found: %s", input.FilePath))
		}
		return errorResult(fmt.Sprintf("cannot access file: %v", err))
	}

	// Get charset hint from .editorconfig
	hintCharset := FindEditorConfigCharset(input.FilePath)

	// If expected_hash is specified, compare with SHA-256 of original file bytes
	if input.ExpectedHash != "" {
		actualHash, err := common.ComputeFileHash(input.FilePath)
		if err != nil {
			return errorResult(fmt.Sprintf("failed to compute file hash: %v", err))
		}
		if !strings.EqualFold(input.ExpectedHash, actualHash) {
			return errorResult(fmt.Sprintf("hash mismatch: expected %s, got %s. File may have been modified by another process.", input.ExpectedHash, actualHash))
		}
	}

	// Read file (with encoding detection)
	content, encInfo, err := common.ReadFileWithEncoding(input.FilePath, hintCharset)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to read file: %v", err))
	}

	// Determine indentation style
	var fileStyle IndentStyle
	if input.IndentStyle != "" {
		parsed, err := parseIndentStyleOption(input.IndentStyle)
		if err != nil {
			return errorResult(fmt.Sprintf("invalid indent_style: %v", err))
		}
		fileStyle = parsed
	} else {
		fileStyle = DetectIndent(input.FilePath, content)
	}

	// Execute replacement (when indent_style is explicitly specified, new_string is also force-converted to fileStyle)
	forceStyle := input.IndentStyle != ""
	result := Replace(content, input.OldString, input.NewString, common.FlexBool(input.ReplaceAll), fileStyle, forceStyle)
	if !result.Applied {
		return errorResult(result.Message)
	}

	// If dry-run, return preview without writing
	if common.FlexBool(input.DryRun) {
		preview := dryRunPreview(content, result.Content, input.FilePath)
		msg := fmt.Sprintf("[DRY RUN] would %s (%s, encoding=%s)\n\n%s", result.Message, input.FilePath, encInfo.Charset, preview)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, EditOutput{Result: msg}, nil
	}

	// Write file (preserve original encoding)
	if err := common.WriteFileWithEncoding(input.FilePath, result.Content, encInfo); err != nil {
		return errorResult(fmt.Sprintf("failed to write file: %v", err))
	}

	msg := fmt.Sprintf("OK: %s (%s, encoding=%s)", result.Message, input.FilePath, encInfo.Charset)

	// Add warning if encoding detection confidence is low
	if warning := common.EncodingWarning(encInfo); warning != "" {
		msg += warning
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, EditOutput{Result: msg}, nil
}

// Register registers the Edit tool with the MCP server.
func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "edit",
		Description: `Replaces old_string with new_string in the specified file.
Smart indentation: auto-converts between tabs and spaces to match the file's style.
Encoding-aware: preserves original file encoding (UTF-8, EUC-KR, Shift-JIS, UTF-8 BOM, etc.).
Reads .editorconfig for indentation settings.
Use dry_run=true to preview changes without modifying the file.`,
	}, Handle)
}

// parseIndentStyleOption parses the indent_style option string.
// "tabs" → UseTabs=true, "spaces-4" → UseTabs=false, IndentSize=4
func parseIndentStyleOption(s string) (IndentStyle, error) {
	s = strings.ToLower(strings.TrimSpace(s))

	if s == "tabs" || s == "tab" {
		return IndentStyle{UseTabs: true, IndentSize: 4}, nil
	}

	if strings.HasPrefix(s, "spaces-") || strings.HasPrefix(s, "space-") {
		parts := strings.SplitN(s, "-", 2)
		if len(parts) == 2 {
			n, err := strconv.Atoi(parts[1])
			if err != nil || n < 1 || n > 8 {
				return IndentStyle{}, fmt.Errorf("invalid indent size: %s (must be 1-8)", parts[1])
			}
			return IndentStyle{UseTabs: false, IndentSize: n}, nil
		}
	}

	if s == "spaces" || s == "space" {
		return IndentStyle{UseTabs: false, IndentSize: 4}, nil
	}

	return IndentStyle{}, fmt.Errorf("expected 'tabs', 'spaces', or 'spaces-N' (e.g. spaces-4), got '%s'", s)
}

// dryRunPreview shows the diff between before and after in a simple diff format.
// Includes 3 lines of context around changed lines.
func dryRunPreview(before, after, filePath string) string {
	oldLines := strings.Split(before, "\n")
	newLines := strings.Split(after, "\n")

	// Find changed range (remove common prefix and suffix)
	prefixLen := 0
	minLen := len(oldLines)
	if len(newLines) < minLen {
		minLen = len(newLines)
	}
	for prefixLen < minLen && oldLines[prefixLen] == newLines[prefixLen] {
		prefixLen++
	}

	suffixLen := 0
	for suffixLen < minLen-prefixLen &&
		oldLines[len(oldLines)-1-suffixLen] == newLines[len(newLines)-1-suffixLen] {
		suffixLen++
	}

	// Calculate context range
	ctxStart := prefixLen - 3
	if ctxStart < 0 {
		ctxStart = 0
	}
	ctxEndOld := len(oldLines) - suffixLen + 3
	if ctxEndOld > len(oldLines) {
		ctxEndOld = len(oldLines)
	}
	ctxEndNew := len(newLines) - suffixLen + 3
	if ctxEndNew > len(newLines) {
		ctxEndNew = len(newLines)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("--- %s (before)\n+++ %s (after)\n", filePath, filePath))

	// Common prefix context
	for i := ctxStart; i < prefixLen; i++ {
		sb.WriteString(" " + oldLines[i] + "\n")
	}
	// Removed lines
	for i := prefixLen; i < len(oldLines)-suffixLen; i++ {
		sb.WriteString("-" + oldLines[i] + "\n")
	}
	// Added lines
	for i := prefixLen; i < len(newLines)-suffixLen; i++ {
		sb.WriteString("+" + newLines[i] + "\n")
	}
	// Common suffix context
	endOld := len(oldLines) - suffixLen
	for i := endOld; i < ctxEndOld; i++ {
		sb.WriteString(" " + oldLines[i] + "\n")
	}

	return sb.String()
}

func errorResult(msg string) (*mcp.CallToolResult, EditOutput, error) {
	r := &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}
	return r, EditOutput{Result: msg}, nil
}
