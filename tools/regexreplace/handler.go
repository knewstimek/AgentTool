package regexreplace

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"regexp/syntax"
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
	Path        string      `json:"path,omitempty" jsonschema:"Absolute or workspace-relative file or directory to process"`
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
	resolvedPath, err := common.ResolveRequestPath(ctx, req, input.Path)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot resolve path: %v", err))
	}
	input.Path = resolvedPath

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
	// Counted while scanning so a "no matches" answer can point at the real
	// reason instead of guessing from the pattern text alone.
	stats := &scanStats{}

	if fi.IsDir() {
		results, err = processDir(input.Path, input.Glob, re, input.Replacement, dryRun, maxFiles, stats)
	} else {
		result, singleErr := processFile(input.Path, re, input.Replacement, dryRun, stats)
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
		sb.WriteString(crlfHint(input.Pattern, stats))
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

// deliberateLineEndingWork reports whether the caller is converting line
// endings rather than editing text that happens to span lines. Those two need
// opposite handling of the replacement: ordinary text must follow the region it
// lands in, while a conversion must reach disk exactly as written -- normalizing
// "\r\n" -> "\n" back to the region puts the CR straight back and reports
// replacements that changed nothing.
//
// An explicit CR in the replacement states which bytes are wanted. In the
// pattern only a MANDATORY CR counts: "\r\n" is a conversion, while the
// defensive "\r?\n" and "(?:\r\n|\n)" forms recommended for matching either
// style are not.
func deliberateLineEndingWork(pattern, replacement string) bool {
	if strings.ContainsRune(replacement, '\r') {
		return true
	}
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return false
	}
	return requiresCR(parsed)
}

func requiresCR(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if r == '\r' {
				return true
			}
		}
		return false
	case syntax.OpQuest, syntax.OpStar:
		return false // optional, so the CR is not being targeted
	case syntax.OpRepeat:
		if re.Min == 0 {
			return false
		}
	case syntax.OpAlternate:
		// Every branch must require one, or the pattern is matching either style.
		for _, sub := range re.Sub {
			if !requiresCR(sub) {
				return false
			}
		}
		return true
	}
	for _, sub := range re.Sub {
		if requiresCR(sub) {
			return true
		}
	}
	return false
}

// scanStats records what the scan saw, so a "no matches" answer can be
// explained with evidence instead of a guess.
type scanStats struct {
	filesScanned int
	crlfFiles    int
}

// crlfHint explains a miss that is really a line-ending mismatch. The pattern
// is matched against decoded text with its newlines intact, so a literal \n
// cannot match a CRLF ending and an end anchor lands before the CR, not after
// it. Only emitted when a scanned file actually uses CRLF -- an agent should
// not be sent chasing a line-ending theory on an LF-only tree.
func crlfHint(pattern string, stats *scanStats) string {
	if stats == nil || stats.crlfFiles == 0 {
		return ""
	}
	where := fmt.Sprintf("%d of %d scanned file(s) use CRLF line endings", stats.crlfFiles, stats.filesScanned)
	switch {
	case strings.Contains(pattern, `\n`) || strings.Contains(pattern, "\n"):
		return fmt.Sprintf(". %s, and a literal \\n does not match a CRLF ending -- use \\r?\\n", where)
	case strings.Contains(pattern, "(?m)") && strings.Contains(pattern, "$"):
		return fmt.Sprintf(". %s, and with (?m) the $ anchor sits before the CR -- use \\r?$", where)
	case strings.Contains(pattern, "$"):
		return fmt.Sprintf(". %s; note that $ matches at end of text, not end of line (add (?m)), and sits before the CR of a CRLF ending -- use \\r?$", where)
	}
	return ""
}

// fileResult holds the result of processing a single file.
type fileResult struct {
	path     string
	count    int
	previews []string // preview of replacements (for dry run)
}

// processFile applies regex replacement on a single file.
// Returns nil result if no matches found.
func processFile(path string, re *regexp.Regexp, replacement string, dryRun bool, stats *scanStats) (*fileResult, error) {
	hintCharset := edit.FindEditorConfigCharset(path)
	content, encInfo, err := common.ReadFileWithEncoding(path, hintCharset)
	if err != nil {
		return nil, err
	}
	if stats != nil {
		stats.filesScanned++
		if strings.Contains(content, "\r\n") {
			stats.crlfFiles++
		}
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
	// A replacement without newlines has nothing to convert. Otherwise a cursor
	// resolves each match's region in one forward pass over the file, since
	// matches arrive in increasing order.
	fixedRepl := replacement
	var region *common.LineEndingCursor
	if deliberateLineEndingWork(re.String(), replacement) {
		// Converting line endings is the one case where the replacement must
		// reach disk exactly as written: normalizing it to the region would put
		// back the very bytes the caller is replacing, reporting replacements
		// that changed nothing.
	} else if strings.ContainsAny(replacement, "\r\n") {
		region = common.NewLineEndingCursor(content)
		// A file with no newline of its own still needs the replacement
		// converted -- to the default, which is what the cursor falls back to.
		if !strings.ContainsAny(content, "\r\n") {
			fixedRepl = common.NormalizeLineEndings(replacement, common.DetectLineEnding(content))
			region = nil
		}
	}
	var sb strings.Builder
	sb.Grow(len(content))
	prev := 0
	for i, mi := range matches {
		local := fixedRepl
		if region != nil {
			local = common.NormalizeLineEndings(replacement, region.At(mi[0], mi[1]))
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
func processDir(dir, globPattern string, re *regexp.Regexp, replacement string, dryRun bool, maxFiles int, stats *scanStats) ([]fileResult, error) {
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

		result, err := processFile(path, re, replacement, dryRun, stats)
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
Replacement newlines follow the newline style of the region each match sits in, so mixed CRLF/LF files stay intact.
Exception: converting line endings on purpose (pattern "\r\n" -> "\n", or a replacement containing \r) writes the replacement verbatim.
The pattern is matched against decoded text WITHOUT newline normalization: use \r?\n for a line break and \r?$ with (?m) for end-of-line, or a CRLF file will not match.
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
