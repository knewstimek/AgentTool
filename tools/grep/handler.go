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
	MaxResults int    `json:"max_results,omitempty" jsonschema:"Maximum number of matching lines to return. Default: 100"`
}

type GrepOutput struct {
	Matches []string `json:"matches"`
	Count   int      `json:"count"`
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

	fi, err := os.Stat(input.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("path not found: %s", input.Path))
		}
		return errorResult(fmt.Sprintf("cannot access path: %v", err))
	}

	var matches []string
	hasLowConfidence := false

	if fi.IsDir() {
		var dirResult searchDirResult
		dirResult, err = searchDir(input.Path, input.Glob, re, maxResults)
		matches = dirResult.matches
		hasLowConfidence = dirResult.lowConfidenceCount > 0
	} else {
		var fileResult searchFileResult
		fileResult, err = searchFile(input.Path, re, maxResults)
		matches = fileResult.matches
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
	if len(matches) == 0 {
		text = "No matches found"
	}

	// Add warning if any files had low encoding detection confidence
	if hasLowConfidence {
		text += "\n⚠ Some files had low encoding detection confidence. " +
			"Results may be incomplete. Consider setting fallback_encoding via set_config tool " +
			"or adding 'charset' to .editorconfig."
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, GrepOutput{Matches: matches, Count: len(matches)}, nil
}

// searchFileResult is the return value of searchFile.
type searchFileResult struct {
	matches    []string
	lowConfidence bool // file with low encoding detection confidence
}

func searchFile(path string, re *regexp.Regexp, maxResults int) (searchFileResult, error) {
	hintCharset := edit.FindEditorConfigCharset(path)
	content, encInfo, err := common.ReadFileWithEncoding(path, hintCharset)
	if err != nil {
		// Skip files that fail to read (e.g. too large) — return empty result instead of error
		return searchFileResult{}, nil
	}

	result := searchFileResult{
		lowConfidence: common.EncodingWarning(encInfo) != "",
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if re.MatchString(line) {
			result.matches = append(result.matches, fmt.Sprintf("%s:%d:%s", path, lineNum, line))
			if len(result.matches) >= maxResults {
				break
			}
		}
	}
	return result, nil
}

// searchDirResult is the return value of searchDir.
type searchDirResult struct {
	matches          []string
	lowConfidenceCount int // number of files with low encoding detection confidence
}

func searchDir(dir, globPattern string, re *regexp.Regexp, maxResults int) (searchDirResult, error) {
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

		// limit per-file search by subtracting already collected results from total maxResults
		fileResult, err := searchFile(path, re, maxResults-len(result.matches))
		if err != nil {
			return nil // skip files that fail to read
		}
		result.matches = append(result.matches, fileResult.matches...)
		if fileResult.lowConfidence {
			result.lowConfidenceCount++
		}

		if len(result.matches) >= maxResults {
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
Supports glob filtering and case-insensitive search.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, GrepOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, GrepOutput{}, nil
}
