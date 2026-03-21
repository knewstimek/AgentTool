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

	"agent-tool/common"
	"agent-tool/tools/edit"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// errMaxResults is a sentinel error to terminate filepath.Walk early.
// Callers use errors.Is to distinguish it from real errors.
var errMaxResults = errors.New("max results reached")

type GrepInput struct {
	Pattern    string `json:"pattern" jsonschema:"Regular expression pattern to search for"`
	Path       string `json:"path,omitempty" jsonschema:"File or directory to search in (absolute path). Defaults to current directory"`
	Glob       string `json:"glob,omitempty" jsonschema:"Glob pattern to filter files (e.g. *.go). Only used when path is a directory"`
	IgnoreCase bool   `json:"ignore_case,omitempty" jsonschema:"Case insensitive search (default false)"`
	MaxResults int    `json:"max_results,omitempty" jsonschema:"Maximum number of matching lines/files to return. Default: 100"`
	OutputMode string `json:"output_mode,omitempty" jsonschema:"Output mode: 'content' (matching lines with path:line:text, default), 'files_with_matches' (file paths only), 'count' (match count per file)"`
	Context    int    `json:"context,omitempty" jsonschema:"Lines of context before and after each match (like grep -C). Default: 0"`
	Before     int    `json:"before,omitempty" jsonschema:"Lines of context before each match (like grep -B). Overrides context. Default: 0"`
	After      int    `json:"after,omitempty" jsonschema:"Lines of context after each match (like grep -A). Overrides context. Default: 0"`
}

type GrepOutput struct {
	Matches []string `json:"matches"`
	Count   int      `json:"count"`
}

// searchOpts holds computed search options passed to search functions.
type searchOpts struct {
	outputMode string
	before     int
	after      int
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input GrepInput) (*mcp.CallToolResult, GrepOutput, error) {
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
	if input.IgnoreCase {
		flags = "(?i)"
	}
	re, err := regexp.Compile(flags + input.Pattern)
	if err != nil {
		return errorResult(fmt.Sprintf("invalid regex pattern: %v", err))
	}

	maxResults := input.MaxResults
	if maxResults <= 0 {
		maxResults = 100
	}

	// Compute search options
	opts := searchOpts{outputMode: input.OutputMode}
	switch opts.outputMode {
	case "", "content", "files_with_matches", "count":
		// valid
	default:
		return errorResult(fmt.Sprintf("invalid output_mode %q -- use 'content', 'files_with_matches', or 'count'", input.OutputMode))
	}
	if input.Context > 0 {
		opts.before = input.Context
		opts.after = input.Context
	}
	if input.Before > 0 {
		opts.before = input.Before
	}
	if input.After > 0 {
		opts.after = input.After
	}

	fi, err := os.Stat(input.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("path not found: %s", input.Path))
		}
		return errorResult(fmt.Sprintf("cannot access path: %v", err))
	}

	var matches []string
	var matchCount int
	hasLowConfidence := false

	if fi.IsDir() {
		var dirResult searchDirResult
		dirResult, err = searchDir(input.Path, input.Glob, re, maxResults, opts)
		matches = dirResult.matches
		matchCount = dirResult.matchCount
		hasLowConfidence = dirResult.lowConfidenceCount > 0
	} else {
		var fileResult searchFileResult
		fileResult, err = searchFile(input.Path, re, maxResults, opts)
		matches = fileResult.matches
		matchCount = fileResult.matchCount
		hasLowConfidence = fileResult.lowConfidence
	}

	if err != nil {
		return errorResult(fmt.Sprintf("search error: %v", err))
	}

	var sb strings.Builder
	for _, m := range matches {
		sb.WriteString(m)
		sb.WriteString("\n")
	}

	text := sb.String()
	if matchCount == 0 {
		text = "No matches found"
	}

	// Add warning if any files had low encoding detection confidence
	if hasLowConfidence {
		text += "\n\xe2\x9a\xa0 Some files had low encoding detection confidence. " +
			"Results may be incomplete. Consider setting fallback_encoding via set_config tool " +
			"or adding 'charset' to .editorconfig."
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, GrepOutput{Matches: matches, Count: matchCount}, nil
}

// searchFileResult is the return value of searchFile.
type searchFileResult struct {
	matches       []string
	matchCount    int  // actual regex match count (excludes context lines and separators)
	lowConfidence bool // file with low encoding detection confidence
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

	// files_with_matches: short-circuit on first match
	if opts.outputMode == "files_with_matches" {
		scanner := bufio.NewScanner(strings.NewReader(content))
		for scanner.Scan() {
			if re.MatchString(scanner.Text()) {
				result.matches = append(result.matches, path)
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
			result.matches = append(result.matches, fmt.Sprintf("%s:%d", path, len(matchIndices)))
			result.matchCount = 1 // 1 file entry
		}
		return result, nil
	}

	// content mode without context: simple line-by-line (preserves original behavior)
	if opts.before == 0 && opts.after == 0 {
		for _, idx := range matchIndices {
			if result.matchCount >= maxResults {
				break
			}
			result.matches = append(result.matches, fmt.Sprintf("%s:%d:%s", path, idx+1, lines[idx]))
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
			result.matches = append(result.matches, "--")
		}
		for lineIdx := r.start; lineIdx < r.end; lineIdx++ {
			if matchSet[lineIdx] {
				result.matches = append(result.matches, fmt.Sprintf("%s:%d:%s", path, lineIdx+1, lines[lineIdx]))
			} else {
				result.matches = append(result.matches, fmt.Sprintf("%s:%d-%s", path, lineIdx+1, lines[lineIdx]))
			}
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
}

func searchDir(dir, globPattern string, re *regexp.Regexp, maxResults int, opts searchOpts) (searchDirResult, error) {
	result := searchDirResult{}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible files
		}
		if info.IsDir() {
			// skip hidden directories (.git, etc.)
			if strings.HasPrefix(info.Name(), ".") && info.Name() != "." {
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

		// skip binary files (simple heuristic)
		if isBinaryExt(info.Name()) {
			return nil
		}

		remaining := maxResults - result.matchCount
		if remaining <= 0 {
			return errMaxResults
		}

		fileResult, err := searchFile(path, re, remaining, opts)
		if err != nil {
			return nil // skip files that fail to read
		}
		result.matches = append(result.matches, fileResult.matches...)
		result.matchCount += fileResult.matchCount
		if fileResult.lowConfidence {
			result.lowConfidenceCount++
		}

		if result.matchCount >= maxResults {
			return errMaxResults
		}
		return nil
	})

	if err != nil && !errors.Is(err, errMaxResults) {
		return result, err
	}
	return result, nil
}

func isBinaryExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	binaryExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".bin": true, ".obj": true, ".o": true, ".a": true,
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".bmp": true, ".ico": true, ".svg": true,
		".zip": true, ".tar": true, ".gz": true, ".7z": true, ".rar": true,
		".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
		".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
		".mp3": true, ".mp4": true, ".avi": true, ".mov": true,
		".pyc": true, ".class": true,
	}
	return binaryExts[ext]
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "grep",
		Description: `Searches file contents for a regex pattern.
Encoding-aware: auto-detects file encoding.
Can search a single file or recursively search a directory.
Output modes: content (default, matching lines), files_with_matches (paths only), count (match counts).
Context: use before/after/context to include surrounding lines (like grep -B/-A/-C).`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, GrepOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, GrepOutput{}, nil
}
