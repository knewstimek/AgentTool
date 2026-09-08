package glob

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type GlobInput struct {
	Pattern        string `json:"pattern" jsonschema:"Glob pattern to match files (e.g. **/*.go or src/**/*.ts)"`
	Path           string `json:"path,omitempty" jsonschema:"Directory to search. Defaults to configured workspace, MCP client root, or current directory"`
	RelativePaths  *bool  `json:"relative_paths,omitempty" jsonschema:"Return paths relative to the search directory. Default: true"`
	Limit          int    `json:"limit,omitempty" jsonschema:"Maximum paths returned per page. Default: 200, Max: 5000"`
	MaxOutputChars int    `json:"max_output_chars,omitempty" jsonschema:"Maximum returned text characters. Default: 32768, Max: 131072"`
	Cursor         string `json:"cursor,omitempty" jsonschema:"Opaque continuation cursor returned by a previous glob call"`
	IncludeHidden  bool   `json:"include_hidden,omitempty" jsonschema:"Traverse hidden directories. Explicit hidden roots are always searched. Default: false"`
	IncludeIgnored bool   `json:"include_ignored,omitempty" jsonschema:"Include paths excluded by .gitignore/.ignore or the common generated/vendor policy. Default: false"`
}

type GlobOutput struct {
	Files      []string `json:"files"`
	Count      int      `json:"count"`
	Returned   int      `json:"returned"`
	HasMore    bool     `json:"has_more"`
	Truncated  bool     `json:"truncated"`
	NextCursor string   `json:"next_cursor,omitempty"`
}

type globCursor struct {
	Offset    int    `json:"o"`
	Signature string `json:"s"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input GlobInput) (*mcp.CallToolResult, GlobOutput, error) {
	if input.Pattern == "" {
		return errorResult("pattern is required")
	}

	searchDir := input.Path
	if searchDir == "" {
		searchDir = common.RequestWorkspace(ctx, req)
	}
	if !filepath.IsAbs(searchDir) {
		resolved, err := common.ResolveRequestPath(ctx, req, searchDir)
		if err != nil {
			return errorResult(fmt.Sprintf("cannot resolve path: %v", err))
		}
		searchDir = resolved
	}
	searchDir = filepath.Clean(searchDir)
	if fi, err := os.Stat(searchDir); err != nil || !fi.IsDir() {
		return errorResult(fmt.Sprintf("directory not found: %s", searchDir))
	}

	limit := input.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 5000 {
		return errorResult("limit must be at most 5000")
	}
	maxOutputChars := input.MaxOutputChars
	if maxOutputChars <= 0 {
		maxOutputChars = common.DefaultOutputChars
	}
	if maxOutputChars > common.HardOutputChars {
		return errorResult(fmt.Sprintf("max_output_chars must be at most %d", common.HardOutputChars))
	}

	relativePaths := input.RelativePaths == nil || *input.RelativePaths
	signature := globCursorSignature(searchDir, input, relativePaths)
	offset := 0
	if input.Cursor != "" {
		cursor, err := decodeGlobCursor(input.Cursor)
		if err != nil {
			return errorResult(fmt.Sprintf("invalid cursor: %v", err))
		}
		if cursor.Signature != signature {
			return errorResult("cursor does not match this glob query; reuse the same path/pattern/include options")
		}
		offset = cursor.Offset
	}

	matches, skipped, err := findMatches(searchDir, input.Pattern, input.IncludeHidden, input.IncludeIgnored)
	if err != nil {
		return errorResult(fmt.Sprintf("glob error: %v", err))
	}

	type fileWithTime struct {
		path    string
		modTime time.Time
	}
	filesWithTime := make([]fileWithTime, 0, len(matches))
	for _, match := range matches {
		fi, err := os.Stat(match)
		if err != nil {
			skipped++
			continue
		}
		filesWithTime = append(filesWithTime, fileWithTime{path: match, modTime: fi.ModTime()})
	}
	sort.Slice(filesWithTime, func(i, j int) bool {
		if filesWithTime[i].modTime.Equal(filesWithTime[j].modTime) {
			return filesWithTime[i].path < filesWithTime[j].path
		}
		return filesWithTime[i].modTime.After(filesWithTime[j].modTime)
	})
	matches = matches[:0]
	for _, file := range filesWithTime {
		matches = append(matches, file.path)
	}

	total := len(matches)
	if offset > total {
		return errorResult(fmt.Sprintf("cursor offset %d is past the current result count %d; restart without cursor", offset, total))
	}
	end := min(offset+limit, total)
	page := matches[offset:end]
	displayPaths := make([]string, 0, len(page))
	for _, match := range page {
		if relativePaths {
			if rel, err := filepath.Rel(searchDir, match); err == nil {
				displayPaths = append(displayPaths, filepath.ToSlash(rel))
				continue
			}
		}
		displayPaths = append(displayPaths, match)
	}

	var sb strings.Builder
	usedChars := 0
	bodyBudget := maxOutputChars - 512
	if bodyBudget < 256 {
		bodyBudget = maxOutputChars
	}
	returned := make([]string, 0, len(displayPaths))
	for _, displayPath := range displayPaths {
		if !common.AppendWithinRuneBudget(&sb, &usedChars, displayPath+"\n", bodyBudget) {
			break
		}
		returned = append(returned, displayPath)
	}
	if len(returned) == 0 && total == 0 {
		sb.WriteString("No files matched the pattern")
	}

	hasMore := offset+len(returned) < total
	nextCursor := ""
	if hasMore {
		nextCursor = encodeGlobCursor(globCursor{Offset: offset + len(returned), Signature: signature})
	}
	fmt.Fprintf(&sb, "\n[glob: returned=%d; total=%d; skipped=%d; truncated=%t; has_more=%t",
		len(returned), total, skipped, hasMore, hasMore)
	if nextCursor != "" {
		fmt.Fprintf(&sb, "; next_cursor=%s", nextCursor)
	}
	sb.WriteString("]")
	text, finalTruncated := common.TruncateRunes(sb.String(), maxOutputChars, "\n[truncated]")

	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, GlobOutput{
		Files: returned, Count: total, Returned: len(returned), HasMore: hasMore,
		Truncated: hasMore || finalTruncated, NextCursor: nextCursor,
	}, nil
}

// findMatches returns recursive glob matches and a count of paths skipped by
// the default hidden/generated/ignore-file policy or traversal errors.
func findMatches(baseDir, pattern string, includeHidden, includeIgnored bool) ([]string, int, error) {
	var matches []string
	skipped := 0
	ignoreRules := common.LoadRootIgnoreRules(baseDir)
	if strings.Contains(pattern, "**") {
		parts := strings.SplitN(pattern, "**", 2)
		prefix := parts[0]
		suffix := strings.TrimLeft(parts[1], "/\\")
		startDir := filepath.Join(baseDir, filepath.FromSlash(prefix))
		if _, err := os.Stat(startDir); err != nil {
			startDir = baseDir
		}
		err := filepath.Walk(startDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				skipped++
				return nil
			}
			if info.IsDir() {
				if path != startDir {
					if !includeHidden && strings.HasPrefix(info.Name(), ".") {
						skipped++
						return filepath.SkipDir
					}
					if !includeIgnored && common.IsDefaultIgnoredDir(info.Name()) {
						skipped++
						return filepath.SkipDir
					}
				}
				if path != baseDir && !includeIgnored {
					rel, _ := filepath.Rel(baseDir, path)
					if ignoreRules.Match(filepath.ToSlash(rel), true) {
						skipped++
						return filepath.SkipDir
					}
				}
				return nil
			}
			if !includeIgnored {
				rel, _ := filepath.Rel(baseDir, path)
				if ignoreRules.Match(filepath.ToSlash(rel), false) {
					skipped++
					return nil
				}
			}
			if suffix == "" {
				matches = append(matches, path)
				return nil
			}
			matched, _ := filepath.Match(suffix, info.Name())
			if matched {
				matches = append(matches, path)
			}
			return nil
		})
		return matches, skipped, err
	}
	rawMatches, err := filepath.Glob(filepath.Join(baseDir, filepath.FromSlash(pattern)))
	if err != nil {
		return nil, skipped, err
	}
	explicitParts := explicitGlobDirParts(pattern)
	for _, match := range rawMatches {
		info, statErr := os.Stat(match)
		if statErr != nil {
			skipped++
			continue
		}
		rel, relErr := filepath.Rel(baseDir, match)
		if relErr != nil {
			skipped++
			continue
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		ignoredAncestor := false
		for i, part := range parts {
			if i == len(parts)-1 && !info.IsDir() {
				break
			}
			if i < explicitParts {
				continue
			}
			if (!includeHidden && strings.HasPrefix(part, ".")) ||
				(!includeIgnored && common.IsDefaultIgnoredDir(part)) {
				ignoredAncestor = true
				break
			}
		}
		if ignoredAncestor || (!includeIgnored && ignoreRules.MatchPath(filepath.ToSlash(rel), info.IsDir())) {
			skipped++
			continue
		}
		matches = append(matches, match)
	}
	return matches, skipped, nil
}

func explicitGlobDirParts(pattern string) int {
	parts := strings.Split(filepath.ToSlash(pattern), "/")
	count := 0
	for i, part := range parts {
		if strings.ContainsAny(part, "*?[") {
			break
		}
		if i < len(parts)-1 {
			count++
		}
	}
	return count
}

func globCursorSignature(searchDir string, input GlobInput, relativePaths bool) string {
	value := fmt.Sprintf("%s\x00%s\x00%t\x00%t\x00%t", searchDir, input.Pattern,
		relativePaths, input.IncludeHidden, input.IncludeIgnored)
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum[:8])
}

func encodeGlobCursor(cursor globCursor) string {
	data, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeGlobCursor(value string) (globCursor, error) {
	var cursor globCursor
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return cursor, fmt.Errorf("not valid base64url")
	}
	if err := json.Unmarshal(data, &cursor); err != nil || cursor.Offset < 0 || cursor.Signature == "" {
		return globCursor{}, fmt.Errorf("malformed cursor payload")
	}
	return cursor, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "glob",
		Description: `Finds files matching a glob pattern.
Supports ** recursive matching and sorts results by modification time (newest first).
Defaults to 200 workspace-relative paths and 32768 characters per page.
Skips hidden paths and paths excluded by root .gitignore/.ignore or the common generated/vendor policy unless explicitly included.
Returns total/has_more/truncated metadata and an opaque next_cursor.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, GlobOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, GlobOutput{}, nil
}
