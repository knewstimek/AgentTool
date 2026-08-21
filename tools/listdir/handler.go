package listdir

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ListDirInput struct {
	Path            string      `json:"path,omitempty" jsonschema:"Absolute path to the directory to list"`
	FilePath        string      `json:"file_path,omitempty" jsonschema:"Alias for path"`
	MaxDepth        interface{} `json:"max_depth,omitempty" jsonschema:"Maximum depth for traversal. Default: 3"`
	MaxEntries      interface{} `json:"max_entries,omitempty" jsonschema:"Maximum entries to return per page. Default: 500, maximum: 10000"`
	Cursor          string      `json:"cursor,omitempty" jsonschema:"Opaque continuation cursor returned by a previous listdir call"`
	RelativePaths   interface{} `json:"relative_paths,omitempty" jsonschema:"Show paths relative to the root. Saves tokens: true or false. Default: false"`
	Flat            *bool       `json:"flat,omitempty" jsonschema:"Flat listing without tree connectors (one path per line). Default: true"`
	DirectoriesOnly interface{} `json:"directories_only,omitempty" jsonschema:"Return directories only while still traversing them: true or false. Default: false"`
	FilesOnly       interface{} `json:"files_only,omitempty" jsonschema:"Return files only: true or false. Default: false"`
	NamePattern     string      `json:"name_pattern,omitempty" jsonschema:"Glob matched against each entry name, for example A* or *.go"`
	Include         []string    `json:"include,omitempty" jsonschema:"Additional entry-name glob patterns. An entry is included when any pattern matches"`
	CountsOnly      interface{} `json:"counts_only,omitempty" jsonschema:"Return matching directory/file counts without listing names: true or false. Default: false"`
}

type ListDirOutput struct {
	Tree          string `json:"tree"`
	TotalFiles    int    `json:"total_files"`
	TotalDirs     int    `json:"total_dirs"`
	ReturnedFiles int    `json:"returned_files"`
	ReturnedDirs  int    `json:"returned_dirs"`
	Truncated     bool   `json:"truncated"`
	HasMore       bool   `json:"has_more"`
	NextCursor    string `json:"next_cursor,omitempty"`
}

const (
	defaultMaxEntries = 500
	hardMaxEntries    = 10000
	cursorVersion     = 1
)

var errPageFull = errors.New("listdir page full")

// Directories skipped during recursion. Their own names can still be returned.
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"__pycache__":  true,
	".next":        true,
	".nuxt":        true,
	"dist":         true,
	"build":        true,
	".cache":       true,
}

type cursorPayload struct {
	Version     int    `json:"v"`
	Fingerprint string `json:"q"`
	LastPath    string `json:"last"`
}

type querySpec struct {
	Root            string   `json:"root"`
	MaxDepth        int      `json:"max_depth"`
	DirectoriesOnly bool     `json:"directories_only"`
	FilesOnly       bool     `json:"files_only"`
	Patterns        []string `json:"patterns"`
}

type listedEntry struct {
	relPath  string
	fullPath string
	name     string
	parent   string
	depth    int
	isDir    bool
}

type walker struct {
	ctx             context.Context
	root            string
	maxDepth        int
	maxEntries      int
	directoriesOnly bool
	filesOnly       bool
	patterns        []string
	countsOnly      bool
	after           string
	cursorFound     bool
	hasMore         bool
	entries         []listedEntry
	files           int
	dirs            int
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input ListDirInput) (*mcp.CallToolResult, ListDirOutput, error) {
	if input.Path == "" {
		input.Path = input.FilePath
	}
	if input.Path == "" {
		return errorResult("path is required")
	}
	if !filepath.IsAbs(input.Path) {
		return errorResult("path must be an absolute path")
	}
	input.Path = filepath.Clean(input.Path)

	fi, err := os.Lstat(input.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("directory not found: %s", input.Path))
		}
		return errorResult(fmt.Sprintf("cannot access path: %v", err))
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		if !common.GetAllowSymlinks() {
			return errorResult("path is a symlink; enable via set_config allow_symlinks=true")
		}
		target, statErr := os.Stat(input.Path)
		if statErr != nil || !target.IsDir() {
			return errorResult(fmt.Sprintf("path is not a directory: %s", input.Path))
		}
	} else if !fi.IsDir() {
		return errorResult(fmt.Sprintf("path is not a directory: %s", input.Path))
	}

	maxDepth, ok := common.FlexInt(input.MaxDepth)
	if !ok {
		return errorResult("max_depth must be an integer")
	}
	if maxDepth <= 0 {
		maxDepth = 3
	}

	maxEntries, ok := common.FlexInt(input.MaxEntries)
	if !ok {
		return errorResult("max_entries must be an integer")
	}
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	if maxEntries > hardMaxEntries {
		return errorResult(fmt.Sprintf("max_entries must be at most %d", hardMaxEntries))
	}

	directoriesOnly := common.FlexBool(input.DirectoriesOnly)
	filesOnly := common.FlexBool(input.FilesOnly)
	if directoriesOnly && filesOnly {
		return errorResult("directories_only and files_only cannot both be true")
	}
	countsOnly := common.FlexBool(input.CountsOnly)
	if countsOnly && input.Cursor != "" {
		return errorResult("cursor cannot be used with counts_only; counts_only scans all matching entries")
	}

	patterns := append([]string(nil), input.Include...)
	if input.NamePattern != "" {
		patterns = append(patterns, input.NamePattern)
	}
	for _, pattern := range patterns {
		if pattern == "" {
			return errorResult("include patterns must not be empty")
		}
		if _, matchErr := filepath.Match(pattern, "probe"); matchErr != nil {
			return errorResult(fmt.Sprintf("invalid name glob %q: %v", pattern, matchErr))
		}
	}

	spec := querySpec{
		Root:            filepath.ToSlash(input.Path),
		MaxDepth:        maxDepth,
		DirectoriesOnly: directoriesOnly,
		FilesOnly:       filesOnly,
		Patterns:        patterns,
	}
	fingerprint := queryFingerprint(spec)
	after := ""
	if input.Cursor != "" {
		payload, decodeErr := decodeCursor(input.Cursor)
		if decodeErr != nil {
			return errorResult(fmt.Sprintf("invalid cursor: %v", decodeErr))
		}
		if payload.Version != cursorVersion || payload.Fingerprint != fingerprint {
			return errorResult("cursor does not match this path, depth, or filter query; restart without cursor")
		}
		after = payload.LastPath
	}

	w := &walker{
		ctx:             ctx,
		root:            input.Path,
		maxDepth:        maxDepth,
		maxEntries:      maxEntries,
		directoriesOnly: directoriesOnly,
		filesOnly:       filesOnly,
		patterns:        patterns,
		countsOnly:      countsOnly,
		after:           after,
		cursorFound:     after == "",
	}
	err = w.walk(input.Path, 0)
	if err != nil && !errors.Is(err, errPageFull) {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return errorResult(fmt.Sprintf("directory listing canceled: %v", err))
		}
		return errorResult(fmt.Sprintf("directory listing failed: %v", err))
	}
	if after != "" && !w.cursorFound {
		return errorResult("cursor is stale because its last entry no longer exists; restart without cursor")
	}

	if countsOnly {
		text := fmt.Sprintf("(%d directories, %d files)", w.dirs, w.files)
		return successResult(text, ListDirOutput{
			Tree: text, TotalFiles: w.files, TotalDirs: w.dirs,
			ReturnedFiles: w.files, ReturnedDirs: w.dirs,
		})
	}

	flat := true
	if input.Flat != nil {
		flat = *input.Flat
	}
	relative := common.FlexBool(input.RelativePaths)
	text := renderEntries(w.entries, input.Path, flat, relative)
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	text += fmt.Sprintf("(%d directories, %d files returned)", w.dirs, w.files)

	nextCursor := ""
	if w.hasMore && len(w.entries) > 0 {
		nextCursor = encodeCursor(cursorPayload{
			Version: cursorVersion, Fingerprint: fingerprint,
			LastPath: w.entries[len(w.entries)-1].relPath,
		})
		text += fmt.Sprintf("\n(more entries available; call listdir again with cursor=%q)", nextCursor)
	}

	out := ListDirOutput{
		Tree: text, TotalFiles: w.files, TotalDirs: w.dirs,
		ReturnedFiles: w.files, ReturnedDirs: w.dirs,
		Truncated: w.hasMore, HasMore: w.hasMore, NextCursor: nextCursor,
	}
	return successResult(text, out)
}

func (w *walker) walk(dir string, depth int) error {
	if depth >= w.maxDepth {
		return nil
	}
	if err := w.ctx.Err(); err != nil {
		return err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil // Preserve prior behavior: skip inaccessible subdirectories.
	}
	for _, entry := range entries {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 && !common.GetAllowSymlinks() {
			continue
		}

		fullPath := filepath.Join(dir, entry.Name())
		rel, relErr := filepath.Rel(w.root, fullPath)
		if relErr != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		isDir := entry.IsDir()
		eligibleType := (!w.directoriesOnly || isDir) && (!w.filesOnly || !isDir)
		matches := eligibleType && matchesAnyName(entry.Name(), w.patterns)

		if matches {
			if w.countsOnly {
				w.increment(isDir)
			} else if !w.cursorFound {
				if rel == w.after {
					w.cursorFound = true
				}
			} else if len(w.entries) >= w.maxEntries {
				w.hasMore = true
				return errPageFull
			} else {
				w.entries = append(w.entries, listedEntry{
					relPath: rel, fullPath: filepath.ToSlash(fullPath), name: entry.Name(),
					parent: filepath.ToSlash(filepath.Dir(rel)), depth: depth, isDir: isDir,
				})
				w.increment(isDir)
			}
		}

		if isDir && !skipDirs[entry.Name()] {
			if err := w.walk(fullPath, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *walker) increment(isDir bool) {
	if isDir {
		w.dirs++
	} else {
		w.files++
	}
}

func matchesAnyName(name string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, name); matched {
			return true
		}
	}
	return false
}

func renderEntries(entries []listedEntry, root string, flat, relative bool) string {
	var sb strings.Builder
	if flat {
		for _, entry := range entries {
			path := entry.fullPath
			if relative {
				path = entry.relPath
			}
			sb.WriteString(path)
			if entry.isDir {
				sb.WriteString("/")
			}
			sb.WriteString("\n")
		}
		return sb.String()
	}

	if relative {
		sb.WriteString(".\n")
	} else {
		sb.WriteString(root)
		sb.WriteString("\n")
	}

	lastSibling := make(map[string]int)
	entryIndex := make(map[string]int)
	for i, entry := range entries {
		lastSibling[entry.parent] = i
		entryIndex[entry.relPath] = i
	}
	for i, entry := range entries {
		parentPresent := entry.depth == 0
		if entry.depth > 0 {
			_, parentPresent = entryIndex[entry.parent]
		}
		if !parentPresent {
			sb.WriteString("├── ")
			sb.WriteString(entry.relPath)
		} else {
			parts := strings.Split(entry.relPath, "/")
			for level := 0; level < entry.depth; level++ {
				ancestor := strings.Join(parts[:level+1], "/")
				ancestorParent := filepath.ToSlash(filepath.Dir(ancestor))
				if idx, ok := entryIndex[ancestor]; ok && lastSibling[ancestorParent] == idx {
					sb.WriteString("    ")
				} else {
					sb.WriteString("│   ")
				}
			}
			if lastSibling[entry.parent] == i {
				sb.WriteString("└── ")
			} else {
				sb.WriteString("├── ")
			}
			sb.WriteString(entry.name)
		}
		if entry.isDir {
			sb.WriteString("/")
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func queryFingerprint(spec querySpec) string {
	data, _ := json.Marshal(spec)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func encodeCursor(payload cursorPayload) string {
	data, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeCursor(cursor string) (cursorPayload, error) {
	data, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return cursorPayload{}, errors.New("malformed continuation token")
	}
	var payload cursorPayload
	if err := json.Unmarshal(data, &payload); err != nil || payload.LastPath == "" {
		return cursorPayload{}, errors.New("malformed continuation token")
	}
	return payload, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "listdir",
		Description: `Lists directory contents with bounded, pageable output.
Default: flat listing, max_depth=3, max_entries=500.
When has_more=true, pass next_cursor as cursor to fetch the next page.
Filter by type with directories_only or files_only, and by entry-name glob with name_pattern (single) or include (multiple OR patterns, e.g. ["A*", "*.go"]).
Use counts_only=true for counts without names, flat=false for a visual tree, and relative_paths=true to save tokens.
Skips hidden entries and common build/vendor directories during recursion.`,
	}, Handle)
}

// successResult returns text only. Clients that understand structured output
// render it instead of the text, so attaching ListDirOutput here shipped the
// same listing twice and showed the agent the JSON-escaped copy. The cursor
// hint and the counts are already in the text.
func successResult(text string, out ListDirOutput) (*mcp.CallToolResult, ListDirOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, out, nil
}

func errorResult(msg string) (*mcp.CallToolResult, ListDirOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, ListDirOutput{}, nil
}
