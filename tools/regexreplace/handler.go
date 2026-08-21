package regexreplace

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"agent-tool/common"
	"agent-tool/tools/edit"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// errMaxFiles is a sentinel error to terminate filepath.Walk early
// when the file processing limit is reached.
var errMaxFiles = errors.New("max files reached")

type RegexReplaceInput struct {
	Pattern     string      `json:"pattern" jsonschema:"Regular expression pattern to search for"`
	Replacement string      `json:"replacement" jsonschema:"Replacement string. Supports $1, $2 capture groups"`
	Path        string      `json:"path,omitempty" jsonschema:"File or directory to process (absolute path)"`
	FilePath    string      `json:"file_path,omitempty" jsonschema:"Alias for path"`
	Glob        string      `json:"glob,omitempty" jsonschema:"Glob pattern to filter files when path is a directory (e.g. *.go). Only used when path is a directory"`
	IgnoreCase  interface{} `json:"ignore_case,omitempty" jsonschema:"Case insensitive search: true or false. Default: false"`
	DryRun      interface{} `json:"dry_run,omitempty" jsonschema:"Preview changes without modifying files: true or false. Default: false"`
	MaxFiles    interface{} `json:"max_files,omitempty" jsonschema:"Maximum number of files to process in directory mode. Default: 100"`
}

type RegexReplaceOutput struct {
	FilesChanged      int `json:"files_changed"`
	TotalReplacements int `json:"total_replacements"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input RegexReplaceInput) (*mcp.CallToolResult, RegexReplaceOutput, error) {
	dryRun := common.FlexBool(input.DryRun)
	ignoreCase := common.FlexBool(input.IgnoreCase)

	if input.Path == "" {
		input.Path = input.FilePath
	}
	if input.Pattern == "" {
		return errorResult("pattern is required")
	}
	if input.Path == "" {
		return errorResult("path is required")
	}
	if !filepath.IsAbs(input.Path) {
		return errorResult("path must be an absolute path")
	}

	flags := ""
	if ignoreCase {
		flags = "(?i)"
	}
	re, err := regexp.Compile(flags + input.Pattern)
	if err != nil {
		return errorResult(fmt.Sprintf("invalid regex pattern: %v", err))
	}

	maxFiles, _ := common.FlexInt(input.MaxFiles)
	if maxFiles <= 0 {
		maxFiles = 100
	}

	fi, err := os.Stat(input.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("path not found: %s", input.Path))
		}
		return errorResult(fmt.Sprintf("cannot access path: %v", err))
	}

	var results []fileResult

	if fi.IsDir() {
		results, err = processDir(input.Path, input.Glob, re, input.Replacement, dryRun, maxFiles)
	} else {
		result, singleErr := processFile(input.Path, re, input.Replacement, dryRun)
		if singleErr != nil {
			return errorResult(fmt.Sprintf("failed to process file: %v", singleErr))
		}
		if result != nil {
			results = append(results, *result)
		}
	}

	if err != nil {
		return errorResult(fmt.Sprintf("processing error: %v", err))
	}

	// Build summary
	var sb strings.Builder
	totalReplacements := 0
	filesChanged := 0

	for _, r := range results {
		filesChanged++
		totalReplacements += r.count
		if dryRun {
			sb.WriteString(fmt.Sprintf("[DRY RUN] %s: %d replacement(s)\n", r.path, r.count))
			// Show up to 3 preview lines
			for i, preview := range r.previews {
				if i >= 3 {
					sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(r.previews)-3))
					break
				}
				sb.WriteString(fmt.Sprintf("  %s\n", preview))
			}
		} else {
			sb.WriteString(fmt.Sprintf("%s: %d replacement(s)\n", r.path, r.count))
		}
	}

	if filesChanged == 0 {
		sb.WriteString("No matches found")
		// The pattern side is matched against raw bytes, so a literal \n never
		// matches a CRLF line ending. Say so rather than leaving the agent to
		// guess why an obviously-present pattern missed.
		if strings.Contains(input.Pattern, `\n`) || strings.Contains(input.Pattern, "\n") {
			sb.WriteString(". Note: a literal \\n does not match CRLF line endings -- use \\r?\\n if the file may be CRLF")
		}
	} else {
		action := "Changed"
		if dryRun {
			action = "Would change"
		}
		sb.WriteString(fmt.Sprintf("\n%s %d file(s), %d total replacement(s)", action, filesChanged, totalReplacements))
	}

	// The replacement is agent-authored text heading for disk, same as an edit's
	// new_string: it carries the same escape-typo and corruption exposure, and
	// here it is written across many files at once.
	sb.WriteString(common.TextGuardNotice(input.Replacement))

	return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}},
		}, RegexReplaceOutput{
			FilesChanged:      filesChanged,
			TotalReplacements: totalReplacements,
		}, nil
}

// fileResult holds the result of processing a single file.
type fileResult struct {
	path     string
	count    int
	previews []string // preview of replacements (for dry run)
}

// processFile applies regex replacement on a single file.
// Returns nil result if no matches found.
func processFile(path string, re *regexp.Regexp, replacement string, dryRun bool) (*fileResult, error) {
	hintCharset := edit.FindEditorConfigCharset(path)
	content, encInfo, err := common.ReadFileWithEncoding(path, hintCharset)
	if err != nil {
		return nil, err
	}

	// Submatch indices, not just match text: the replacement's line endings are
	// decided per match position, and $1 expansion needs the capture offsets.
	matches := re.FindAllStringSubmatchIndex(content, -1)
	if len(matches) == 0 {
		return nil, nil
	}

	result := &fileResult{
		path:  path,
		count: len(matches),
	}

	// MCP/JSON strings normally carry LF newlines, so the replacement's newlines
	// are converted to the file's. Per match rather than per file: in a mixed
	// file (a CRLF-era file with later LF-only edits) one dominant choice would
	// push CRLF into the LF regions and vice versa.
	dominant := common.DetectLineEnding(content)
	// Nothing to convert when the replacement carries no newline, and nothing to
	// look up when the file carries none either. Both checks keep a many-match
	// run linear instead of scanning for a neighbouring newline per match.
	perMatch := strings.ContainsAny(replacement, "\r\n") && strings.ContainsAny(content, "\r\n")
	var sb strings.Builder
	sb.Grow(len(content))
	prev := 0
	for i, mi := range matches {
		local := replacement
		if perMatch {
			local = common.NormalizeLineEndings(replacement, common.LineEndingAround(content, mi[0], mi[1], dominant))
		}
		expanded := string(re.ExpandString(nil, local, content, mi))
		if dryRun {
			// Preview the first few matches exactly as they would be written.
			if i < 5 {
				result.previews = append(result.previews, fmt.Sprintf("%q -> %q", content[mi[0]:mi[1]], expanded))
			}
			continue
		}
		sb.WriteString(content[prev:mi[0]])
		sb.WriteString(expanded)
		prev = mi[1]
	}
	if dryRun {
		return result, nil
	}
	sb.WriteString(content[prev:])

	// Write back with original encoding (atomic write via common.WriteFileWithEncoding)
	if err := common.WriteFileWithEncoding(path, sb.String(), encInfo); err != nil {
		return nil, fmt.Errorf("failed to write %s: %w", path, err)
	}

	return result, nil
}

// processDir walks a directory and applies regex replacement to matching files.
func processDir(dir, globPattern string, re *regexp.Regexp, replacement string, dryRun bool, maxFiles int) ([]fileResult, error) {
	var results []fileResult
	filesProcessed := 0

	// WalkDir uses Lstat internally, so d.Type() correctly detects symlinks
	// (unlike filepath.Walk which follows symlinks and hides them).
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible files
		}

		// Skip symlinks to prevent symlink-based traversal attacks
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			// Skip hidden directories (.git, etc.)
			if strings.HasPrefix(d.Name(), ".") && d.Name() != "." {
				return filepath.SkipDir
			}
			return nil
		}

		// Glob filter
		if globPattern != "" {
			matched, _ := filepath.Match(globPattern, d.Name())
			if !matched {
				return nil
			}
		}

		// Skip binary files. Content sniffing matters more here than in grep:
		// a bad match would rewrite the file, and corrupting an on-disk index
		// (.codegraph.db and friends) is silent until the next query fails.
		if common.IsBinaryFile(path) {
			return nil
		}

		result, err := processFile(path, re, replacement, dryRun)
		if err != nil {
			return nil // skip files that fail
		}
		if result != nil {
			results = append(results, *result)
			filesProcessed++
			if filesProcessed >= maxFiles {
				return errMaxFiles
			}
		}
		return nil
	})

	if err != nil && !errors.Is(err, errMaxFiles) {
		return results, err
	}
	return results, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "regexreplace",
		Description: `Performs regex find-and-replace across files.
Encoding-aware: preserves original file encoding.
Converts replacement newlines to each file's dominant newline style.
Supports single file or recursive directory mode with glob filtering.
Supports capture group replacement ($1, $2, ${name}).
Skips binary files. Use dry_run=true to preview changes.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, RegexReplaceOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, RegexReplaceOutput{}, nil
}
