package listdir

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ListDirInput struct {
	Path          string `json:"path,omitempty" jsonschema:"Absolute path to the directory to list"`
	FilePath      string `json:"file_path,omitempty" jsonschema:"Alias for path"`
	MaxDepth      int    `json:"max_depth,omitempty" jsonschema:"Maximum depth for tree traversal. Default: 3"`
	RelativePaths interface{} `json:"relative_paths,omitempty" jsonschema:"Show the root as '.' instead of the full absolute path. Saves tokens in output: true or false. Default: false"`
	Flat          *bool  `json:"flat,omitempty" jsonschema:"Flat listing without tree connectors (one path per line). Default: true"`
}

type ListDirOutput struct {
	Tree       string `json:"tree"`
	TotalFiles int    `json:"total_files"`
	TotalDirs  int    `json:"total_dirs"`
}

const maxEntries = 10000

// Directories to skip
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

	// Use Lstat to detect symlinks (consistent with delete/rename/mkdir)
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
		// Resolve symlink target to check if it's a directory
		target, err := os.Stat(input.Path)
		if err != nil || !target.IsDir() {
			return errorResult(fmt.Sprintf("path is not a directory: %s", input.Path))
		}
	} else if !fi.IsDir() {
		return errorResult(fmt.Sprintf("path is not a directory: %s", input.Path))
	}

	maxDepth := input.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 3
	}

	// Default flat=true (token-efficient for AI agents)
	flat := true
	if input.Flat != nil {
		flat = *input.Flat
	}

	relativePaths := common.FlexBool(input.RelativePaths)

	var sb strings.Builder
	totalFiles := 0
	totalDirs := 0

	if flat {
		buildFlat(&sb, input.Path, input.Path, 0, maxDepth, relativePaths, &totalFiles, &totalDirs)
	} else {
		if relativePaths {
			sb.WriteString(".\n")
		} else {
			sb.WriteString(input.Path)
			sb.WriteString("\n")
		}
		buildTree(&sb, input.Path, "", 0, maxDepth, &totalFiles, &totalDirs)
	}

	if totalFiles+totalDirs >= maxEntries {
		sb.WriteString(fmt.Sprintf("\n(truncated at %d entries)", maxEntries))
	}
	summary := fmt.Sprintf("\n(%d directories, %d files)", totalDirs, totalFiles)
	sb.WriteString(summary)

	text := sb.String()
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, ListDirOutput{Tree: text, TotalFiles: totalFiles, TotalDirs: totalDirs}, nil
}

func buildFlat(sb *strings.Builder, root, dir string, depth, maxDepth int, relative bool, totalFiles, totalDirs *int) {
	if depth >= maxDepth || *totalFiles+*totalDirs >= maxEntries {
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		// Skip symlinks unless explicitly allowed via set_config
		if entry.Type()&os.ModeSymlink != 0 && !common.GetAllowSymlinks() {
			continue
		}
		if *totalFiles+*totalDirs >= maxEntries {
			return
		}

		fullPath := filepath.Join(dir, entry.Name())

		if entry.IsDir() {
			*totalDirs++
			if skipDirs[entry.Name()] {
				continue
			}
			if relative {
				rel, _ := filepath.Rel(root, fullPath)
				sb.WriteString(filepath.ToSlash(rel))
			} else {
				sb.WriteString(filepath.ToSlash(fullPath))
			}
			sb.WriteString("/\n")
			buildFlat(sb, root, fullPath, depth+1, maxDepth, relative, totalFiles, totalDirs)
		} else {
			*totalFiles++
			if relative {
				rel, _ := filepath.Rel(root, fullPath)
				sb.WriteString(filepath.ToSlash(rel))
			} else {
				sb.WriteString(filepath.ToSlash(fullPath))
			}
			sb.WriteString("\n")
		}
	}
}

func buildTree(sb *strings.Builder, dir, prefix string, depth, maxDepth int, totalFiles, totalDirs *int) {
	if depth >= maxDepth || *totalFiles+*totalDirs >= maxEntries {
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	// Filter out hidden files/directories and symlinks
	var visible []os.DirEntry
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") && (e.Type()&os.ModeSymlink == 0 || common.GetAllowSymlinks()) {
			visible = append(visible, e)
		}
	}

	for i, entry := range visible {
		if *totalFiles+*totalDirs >= maxEntries {
			return
		}
		isLast := i == len(visible)-1

		connector := "├── "
		childPrefix := "│   "
		if isLast {
			connector = "└── "
			childPrefix = "    "
		}

		sb.WriteString(prefix)
		sb.WriteString(connector)
		sb.WriteString(entry.Name())

		if entry.IsDir() {
			sb.WriteString("/\n")
			*totalDirs++

			if skipDirs[entry.Name()] {
				sb.WriteString(prefix)
				sb.WriteString(childPrefix)
				sb.WriteString("└── ...\n")
				continue
			}

			buildTree(sb, filepath.Join(dir, entry.Name()), prefix+childPrefix, depth+1, maxDepth, totalFiles, totalDirs)
		} else {
			sb.WriteString("\n")
			*totalFiles++
		}
	}
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "listdir",
		Description: `Lists directory contents.
Default: flat listing (one path per line, token-efficient for AI agents).
Use flat=false for visual tree structure with connectors (├── └──).
Skips hidden directories and common build/vendor directories.
Use max_depth to control traversal depth (default: 3).
Use relative_paths=true to show root as '.' instead of full path (saves tokens).`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, ListDirOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, ListDirOutput{}, nil
}
