package grep

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"agent-tool/common"
	"agent-tool/tools/edit"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// errMaxResults is a sentinel error to terminate filepath.Walk early.
// Callers use errors.Is to distinguish it from real errors.
var (
	errMaxResults = errors.New("max results reached")
	errMaxOutput  = errors.New("max output reached")
)

const (
	defaultMaxResults     = 100
	hardMaxResults        = 100000
	defaultMaxLineChars   = 4000
	hardMaxLineChars      = 100000
	defaultMaxOutputChars = 100000
	hardMaxOutputChars    = 1000000
	hardMaxContextLines   = 1000
)

type GrepInput struct {
	Pattern        string      `json:"pattern" jsonschema:"Regular expression pattern to search for"`
	Path           string      `json:"path,omitempty" jsonschema:"File or directory to search in (absolute path). Defaults to current directory"`
	FilePath       string      `json:"file_path,omitempty" jsonschema:"Alias for path"`
	Glob           string      `json:"glob,omitempty" jsonschema:"Glob pattern to filter files (e.g. *.go). Only used when path is a directory"`
	IgnoreCase     interface{} `json:"ignore_case,omitempty" jsonschema:"Case insensitive search: true or false. Default: false"`
	Recursive      interface{} `json:"recursive,omitempty" jsonschema:"Recurse into subdirectories: true or false. Default: true"`
	MaxResults     interface{} `json:"max_results,omitempty" jsonschema:"Maximum matching lines/files to inspect for the result. Default: 100, Max: 100000. Total returned text is also bounded by max_output_chars"`
	OutputMode     string      `json:"output_mode,omitempty" jsonschema:"Output mode: 'content' (matching lines with path:line:text, default), 'files_with_matches' (file paths only), 'count' (match count per file)"`
	Context        interface{} `json:"context,omitempty" jsonschema:"Lines of context before and after each match (like grep -C). Default: 0, Max: 1000"`
	Before         interface{} `json:"before,omitempty" jsonschema:"Lines of context before each match (like grep -B). Overrides context. Default: 0, Max: 1000"`
	After          interface{} `json:"after,omitempty" jsonschema:"Lines of context after each match (like grep -A). Overrides context. Default: 0, Max: 1000"`
	MaxLineChars   interface{} `json:"max_line_chars,omitempty" jsonschema:"Maximum characters returned from one matching or context line. Default: 4000, Max: 100000"`
	MaxOutputChars interface{} `json:"max_output_chars,omitempty" jsonschema:"Maximum total result characters. Default: 100000, Max: 1000000"`
}

type GrepOutput struct {
	Matches       []string `json:"matches"`
	Count         int      `json:"count"`
	ReturnedLines int      `json:"returned_lines"`
	Truncated     bool     `json:"truncated"`
	LimitReached  bool     `json:"limit_reached"`
}

// searchOpts holds computed search options passed to search functions.
type searchOpts struct {
	outputMode     string
	before         int
	after          int
	showPath       bool // include file path prefix on each line (true for directory search)
	maxLineChars   int
	maxOutputChars int
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input GrepInput) (*mcp.CallToolResult, GrepOutput, error) {
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
	if common.FlexBool(input.IgnoreCase) {
		flags = "(?i)"
	}
	re, err := regexp.Compile(flags + input.Pattern)
	if err != nil {
		return errorResult(fmt.Sprintf("invalid regex pattern: %v", err))
	}

	maxResults, ok := common.FlexInt(input.MaxResults)
	if !ok {
		return errorResult("max_results must be an integer")
	}
	if maxResults <= 0 {
		maxResults = defaultMaxResults
	}
	if maxResults > hardMaxResults {
		return errorResult(fmt.Sprintf("max_results must be at most %d; use a narrower path/pattern or multiple calls", hardMaxResults))
	}
	ctxLines, ok := common.FlexInt(input.Context)
	if !ok {
		return errorResult("context must be an integer")
	}
	beforeLines, ok := common.FlexInt(input.Before)
	if !ok {
		return errorResult("before must be an integer")
	}
	afterLines, ok := common.FlexInt(input.After)
	if !ok {
		return errorResult("after must be an integer")
	}
	for name, value := range map[string]int{"context": ctxLines, "before": beforeLines, "after": afterLines} {
		if value < 0 || value > hardMaxContextLines {
			return errorResult(fmt.Sprintf("%s must be between 0 and %d", name, hardMaxContextLines))
		}
	}
	maxLineChars, ok := common.FlexInt(input.MaxLineChars)
	if !ok {
		return errorResult("max_line_chars must be an integer")
	}
	if maxLineChars <= 0 {
		maxLineChars = defaultMaxLineChars
	}
	if maxLineChars > hardMaxLineChars {
		return errorResult(fmt.Sprintf("max_line_chars must be at most %d", hardMaxLineChars))
	}
	maxOutputChars, ok := common.FlexInt(input.MaxOutputChars)
	if !ok {
		return errorResult("max_output_chars must be an integer")
	}
	if maxOutputChars <= 0 {
		maxOutputChars = defaultMaxOutputChars
	}
	if maxOutputChars > hardMaxOutputChars {
		return errorResult(fmt.Sprintf("max_output_chars must be at most %d", hardMaxOutputChars))
	}

	// Compute search options
	opts := searchOpts{outputMode: input.OutputMode, maxLineChars: maxLineChars, maxOutputChars: maxOutputChars}
	switch opts.outputMode {
	case "", "content", "files_with_matches", "count":
		// valid
	default:
		return errorResult(fmt.Sprintf("invalid output_mode %q -- use 'content', 'files_with_matches', or 'count'", input.OutputMode))
	}
	if ctxLines > 0 {
		opts.before = ctxLines
		opts.after = ctxLines
	}
	if beforeLines > 0 {
		opts.before = beforeLines
	}
	if afterLines > 0 {
		opts.after = afterLines
	}

	fi, err := os.Stat(input.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("path not found: %s", input.Path))
		}
		return errorResult(fmt.Sprintf("cannot access path: %v", err))
	}

	// recursive defaults to true; only disable when explicitly false.
	recursive := true
	if input.Recursive != nil && !common.FlexBool(input.Recursive) {
		recursive = false
	}

	// Directory search includes file path on each line; single-file search
	// omits it to save tokens (agent already knows which file it passed).
	opts.showPath = fi.IsDir()

	var matches []string
	var matchCount int
	hasLowConfidence := false
	skippedBinary := 0
	searchOutputTruncated := false

	if fi.IsDir() {
		var dirResult searchDirResult
		dirResult, err = searchDir(input.Path, input.Glob, re, maxResults, opts, recursive)
		matches = dirResult.matches
		matchCount = dirResult.matchCount
		hasLowConfidence = dirResult.lowConfidenceCount > 0
		skippedBinary = dirResult.skippedBinary
		searchOutputTruncated = dirResult.outputTruncated
	} else {
		var fileResult searchFileResult
		fileResult, err = searchFile(input.Path, re, maxResults, opts)
		matches = fileResult.matches
		matchCount = fileResult.matchCount
		hasLowConfidence = fileResult.lowConfidence
		searchOutputTruncated = fileResult.outputTruncated
	}

	if err != nil {
		return errorResult(fmt.Sprintf("search error: %v", err))
	}

	var sb strings.Builder
	usedChars := 0
	displayedMatches := make([]string, 0, len(matches))
	outputTruncated := searchOutputTruncated
	for _, m := range matches {
		line := m + "\n"
		if !common.AppendWithinRuneBudget(&sb, &usedChars, line, maxOutputChars) {
			outputTruncated = true
			break
		}
		displayedMatches = append(displayedMatches, m)
	}

	text := sb.String()
	if matchCount == 0 {
		text = "No matches found"
	}

	// Say what was not searched, so a missing hit is never a silent mystery.
	// Only when something was actually skipped -- otherwise it is pure noise.
	if skippedBinary > 0 {
		if matchCount == 0 {
			text += fmt.Sprintf("\n(%d binary file(s) skipped -- pass one as path to search it directly)", skippedBinary)
		} else {
			text += fmt.Sprintf("\n(%d binary file(s) skipped)", skippedBinary)
		}
	}

	// Add warning if any files had low encoding detection confidence
	if hasLowConfidence {
		text += "\n\xe2\x9a\xa0 Some files had low encoding detection confidence. " +
			"Results may be incomplete. Consider setting fallback_encoding via set_config tool " +
			"or adding 'charset' to .editorconfig."
	}
	if outputTruncated {
		text += fmt.Sprintf("\n[Output truncated at %d characters after %d displayed lines. Narrow path/pattern/context or raise max_output_chars (max %d).]", maxOutputChars, len(displayedMatches), hardMaxOutputChars)
	}
	text, finalTruncated := common.TruncateRunes(text, maxOutputChars, "\n[Output truncated]")
	outputTruncated = outputTruncated || finalTruncated

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, GrepOutput{Matches: displayedMatches, Count: matchCount, ReturnedLines: len(displayedMatches), Truncated: outputTruncated, LimitReached: matchCount >= maxResults || searchOutputTruncated}, nil
}

// searchFileResult is the return value of searchFile.
type searchFileResult struct {
	matches         []string
	matchCount      int  // actual regex match count (excludes context lines and separators)
	lowConfidence   bool // file with low encoding detection confidence
	displayChars    int
	outputTruncated bool
}

func searchFile(path string, re *regexp.Regexp, maxResults int, opts searchOpts) (searchFileResult, error) {
	hintCharset := edit.FindEditorConfigCharset(path)
	content, encInfo, err := common.ReadFileWithEncoding(path, hintCharset)
	if err != nil {
		// Skip files that fail to read (e.g. too large) -- return empty result instead of error
		return searchFileResult{}, nil
	}

	result := searchFileResult{
		lowConfidence: common.EncodingWarning(encInfo) != "",
	}
	appendDisplay := func(line string) bool {
		n := utf8.RuneCountInString(line) + 1 // account for the newline added by Handle
		if result.displayChars+n > opts.maxOutputChars {
			result.outputTruncated = true
			return false
		}
		result.matches = append(result.matches, line)
		result.displayChars += n
		return true
	}

	// files_with_matches: short-circuit on first match
	if opts.outputMode == "files_with_matches" {
		scanner := bufio.NewScanner(strings.NewReader(content))
		for scanner.Scan() {
			if re.MatchString(scanner.Text()) {
				appendDisplay(path)
				result.matchCount = 1
				return result, nil
			}
		}
		return result, nil
	}

	// Split content into lines for indexed access
	lines := strings.Split(content, "\n")
	// Drop trailing empty line caused by final newline
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	// Find all matching line indices
	var matchIndices []int
	for i, line := range lines {
		if re.MatchString(line) {
			matchIndices = append(matchIndices, i)
		}
	}

	// count mode: return "path:count"
	if opts.outputMode == "count" {
		if len(matchIndices) > 0 {
			appendDisplay(fmt.Sprintf("%s:%d", path, len(matchIndices)))
			result.matchCount = 1 // 1 file entry
		}
		return result, nil
	}

	// Line formatting helpers: include path prefix only for directory search
	fmtMatch := func(lineNum int, text string) string {
		text, _ = common.TruncateRunes(text, opts.maxLineChars, "… [line truncated]")
		if opts.showPath {
			return fmt.Sprintf("%s:%d:%s", path, lineNum, text)
		}
		return fmt.Sprintf("%d:%s", lineNum, text)
	}
	fmtContext := func(lineNum int, text string) string {
		text, _ = common.TruncateRunes(text, opts.maxLineChars, "… [line truncated]")
		if opts.showPath {
			return fmt.Sprintf("%s:%d-%s", path, lineNum, text)
		}
		return fmt.Sprintf("%d-%s", lineNum, text)
	}

	// content mode without context: simple line-by-line (preserves original behavior)
	if opts.before == 0 && opts.after == 0 {
		for _, idx := range matchIndices {
			if result.matchCount >= maxResults {
				break
			}
			if !appendDisplay(fmtMatch(idx+1, lines[idx])) {
				break
			}
			result.matchCount++
		}
		return result, nil
	}

	// content mode with context lines
	matchSet := make(map[int]bool)
	for _, idx := range matchIndices {
		matchSet[idx] = true
	}

	// Build display ranges, merging overlapping/adjacent regions
	type lineRange struct{ start, end int }
	var ranges []lineRange
	used := 0
	for _, idx := range matchIndices {
		if used >= maxResults {
			break
		}
		used++
		start := idx - opts.before
		if start < 0 {
			start = 0
		}
		end := idx + opts.after + 1
		if end > len(lines) {
			end = len(lines)
		}
		if len(ranges) > 0 && start <= ranges[len(ranges)-1].end {
			// Merge with previous range
			if end > ranges[len(ranges)-1].end {
				ranges[len(ranges)-1].end = end
			}
		} else {
			ranges = append(ranges, lineRange{start, end})
		}
	}

	// Format output: match lines use ":", context lines use "-" (grep convention)
	for i, r := range ranges {
		if i > 0 {
			if !appendDisplay("--") {
				break
			}
		}
		for lineIdx := r.start; lineIdx < r.end; lineIdx++ {
			var formatted string
			if matchSet[lineIdx] {
				formatted = fmtMatch(lineIdx+1, lines[lineIdx])
			} else {
				formatted = fmtContext(lineIdx+1, lines[lineIdx])
			}
			if !appendDisplay(formatted) {
				break
			}
		}
		if result.outputTruncated {
			break
		}
	}
	result.matchCount = used
	return result, nil
}

// searchDirResult is the return value of searchDir.
type searchDirResult struct {
	matches            []string
	matchCount         int // total match count across all files
	lowConfidenceCount int // number of files with low encoding detection confidence
	skippedBinary      int // binary files not searched
	displayChars       int
	outputTruncated    bool
}

func searchDir(dir, globPattern string, re *regexp.Regexp, maxResults int, opts searchOpts, recursive bool) (searchDirResult, error) {
	result := searchDirResult{}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible files
		}
		if info.IsDir() {
			// Skip hidden directories (.git, etc.)
			if strings.HasPrefix(info.Name(), ".") && info.Name() != "." {
				return filepath.SkipDir
			}
			// When non-recursive, skip subdirectories (but not the root dir itself)
			if !recursive && path != dir {
				return filepath.SkipDir
			}
			return nil
		}

		// glob filter
		if globPattern != "" {
			matched, _ := filepath.Match(globPattern, info.Name())
			if !matched {
				return nil
			}
		}

		// Skip binary files. Extension alone is not enough -- a SQLite index
		// like .codegraph.db stores symbol names as plain text inside binary
		// pages, so every identifier search matched it and dumped multi-KB
		// page fragments (binaries have almost no newlines, so one "line" is
		// huge). A single explicitly-passed file path still gets searched.
		if common.IsBinaryFile(path) {
			result.skippedBinary++
			return nil
		}

		remaining := maxResults - result.matchCount
		if remaining <= 0 {
			return errMaxResults
		}

		fileOpts := opts
		fileOpts.maxOutputChars -= result.displayChars
		if fileOpts.maxOutputChars <= 0 {
			result.outputTruncated = true
			return errMaxOutput
		}
		fileResult, err := searchFile(path, re, remaining, fileOpts)
		if err != nil {
			return nil // skip files that fail to read
		}
		result.matches = append(result.matches, fileResult.matches...)
		result.matchCount += fileResult.matchCount
		result.displayChars += fileResult.displayChars
		if fileResult.lowConfidence {
			result.lowConfidenceCount++
		}
		if fileResult.outputTruncated {
			result.outputTruncated = true
			return errMaxOutput
		}

		if result.matchCount >= maxResults {
			return errMaxResults
		}
		return nil
	})

	if err != nil && !errors.Is(err, errMaxResults) && !errors.Is(err, errMaxOutput) {
		return result, err
	}
	return result, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "grep",
		Description: `Searches file contents for a regex pattern.
Encoding-aware: auto-detects file encoding.
Can search a single file or recursively search a directory.
Output modes: content (default, matching lines), files_with_matches (paths only), count (match counts).
Context: use before/after/context to include surrounding lines (like grep -B/-A/-C).
Large result sets stay usable: max_results supports up to 100000, while max_line_chars
and max_output_chars bound the text returned to the agent.
Directory search skips binary files (extension list + NUL-byte sniff); pass a binary file
directly as path to search it anyway.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, GrepOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, GrepOutput{}, nil
}
