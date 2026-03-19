package glob

import (
	"context"
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
	Pattern       string `json:"pattern" jsonschema:"Glob pattern to match files (e.g. **/*.go or src/**/*.ts)"`
	Path          string `json:"path,omitempty" jsonschema:"Directory to search in (absolute path). Defaults to current directory if empty"`
	RelativePaths bool   `json:"relative_paths,omitempty" jsonschema:"Return paths relative to the search directory instead of absolute paths. Saves tokens in output. Default: false"`
}

type GlobOutput struct {
	Files []string `json:"files"`
	Count int      `json:"count"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input GlobInput) (*mcp.CallToolResult, GlobOutput, error) {
	if input.Pattern == "" {
		return errorResult("pattern is required")
	}

	searchDir := input.Path
	if searchDir == "" {
		if ws := common.GetWorkspace(); ws != "" {
			searchDir = ws
		} else {
			var err error
			searchDir, err = os.Getwd()
			if err != nil {
				return errorResult(fmt.Sprintf("failed to get working directory: %v", err))
			}
		}
	}

	if !filepath.IsAbs(searchDir) {
		return errorResult("path must be an absolute path")
	}

	if _, err := os.Stat(searchDir); os.IsNotExist(err) {
		return errorResult(fmt.Sprintf("directory not found: %s", searchDir))
	}

	matches, err := findMatches(searchDir, input.Pattern)
	if err != nil {
		return errorResult(fmt.Sprintf("glob error: %v", err))
	}

	// Sort by modification time (newest first).
	// Cache modTime in a single pass to avoid O(N log N) syscalls from calling os.Stat
	// in every sort comparison — this limits it to O(N) syscalls.
	type fileWithTime struct {
		path    string
		modTime time.Time
		valid   bool
	}
	filesWithTime := make([]fileWithTime, len(matches))
	for i, m := range matches {
		fi, err := os.Stat(m)
		if err != nil {
			filesWithTime[i] = fileWithTime{path: m}
		} else {
			filesWithTime[i] = fileWithTime{path: m, modTime: fi.ModTime(), valid: true}
		}
	}
	sort.Slice(filesWithTime, func(i, j int) bool {
		if !filesWithTime[i].valid {
			return false // files that failed stat go to the end
		}
		if !filesWithTime[j].valid {
			return true
		}
		return filesWithTime[i].modTime.After(filesWithTime[j].modTime)
	})

	// Exclude files that failed stat (deleted, no permission, etc.) from results.
	// The 500-file limit counts only valid files so the user gets as many results as possible.
	matches = matches[:0]
	for _, ft := range filesWithTime {
		if !ft.valid {
			continue
		}
		matches = append(matches, ft.path)
		if len(matches) >= 500 {
			break
		}
	}

	// Build display paths (relative or absolute)
	displayPaths := matches
	if input.RelativePaths && len(matches) > 0 {
		displayPaths = make([]string, len(matches))
		for i, m := range matches {
			if rel, err := filepath.Rel(searchDir, m); err == nil {
				displayPaths[i] = filepath.ToSlash(rel)
			} else {
				displayPaths[i] = m
			}
		}
	}

	var sb strings.Builder
	for _, m := range displayPaths {
		sb.WriteString(m)
		sb.WriteString("\n")
	}

	text := sb.String()
	if len(matches) == 0 {
		text = "No files matched the pattern"
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, GlobOutput{Files: displayPaths, Count: len(matches)}, nil
}

// findMatches returns file paths in baseDir matching the given pattern.
// The "**" pattern is handled via recursive directory traversal, automatically
// skipping hidden directories (.git, etc.), node_modules, and vendor.
// Examples: "**/*.go" → all .go files under baseDir
//           "src/**/*.ts" → all .ts files under baseDir/src/
func findMatches(baseDir, pattern string) ([]string, error) {
	var matches []string

	// Support ** pattern: recursive traversal.
	// Simple implementation: ** is handled once, and the suffix after ** is matched as a filename glob.
	// Example: "src/**/*.ts" → prefix="src/", suffix="*.ts"
	if strings.Contains(pattern, "**") {
		parts := strings.SplitN(pattern, "**", 2)
		prefix := parts[0]
		suffix := ""
		if len(parts) > 1 {
			suffix = strings.TrimPrefix(parts[1], "/")
			suffix = strings.TrimPrefix(suffix, "\\")
		}

		startDir := filepath.Join(baseDir, filepath.FromSlash(prefix))
		if _, err := os.Stat(startDir); os.IsNotExist(err) {
			startDir = baseDir
		}

		err := filepath.Walk(startDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if strings.HasPrefix(info.Name(), ".") && info.Name() != "." {
					return filepath.SkipDir
				}
				if info.Name() == "node_modules" || info.Name() == "vendor" {
					return filepath.SkipDir
				}
				return nil
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
		return matches, err
	}

	// Standard glob pattern
	fullPattern := filepath.Join(baseDir, filepath.FromSlash(pattern))
	return filepath.Glob(fullPattern)
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "glob",
		Description: `Finds files matching a glob pattern.
Supports ** for recursive directory matching.
Returns matching file paths sorted by modification time (newest first).
Skips hidden directories (.git, etc.) and common vendor directories.
Use relative_paths=true to return paths relative to the search directory (saves tokens).`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, GlobOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, GlobOutput{}, nil
}
