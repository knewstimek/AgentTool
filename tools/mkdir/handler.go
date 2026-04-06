package mkdir

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

type MkdirInput struct {
	Path      string `json:"path,omitempty" jsonschema:"Absolute path of the directory to create,required"`
	FilePath  string `json:"file_path,omitempty" jsonschema:"Alias for path"`
	Recursive *bool  `json:"recursive,omitempty" jsonschema:"Create parent directories as needed (like mkdir -p). Default: true"`
	Mode      string `json:"mode,omitempty" jsonschema:"Directory permission mode in octal (e.g. 0755, 0700). Default: 0755. Applied on Unix/Linux only"`
	DryRun    interface{} `json:"dry_run,omitempty" jsonschema:"Preview what would be created without actually creating: true or false. Default: false"`
}

type MkdirOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input MkdirInput) (*mcp.CallToolResult, MkdirOutput, error) {
	if input.Path == "" {
		input.Path = input.FilePath
	}
	if input.Path == "" {
		return errorResult("path is required")
	}
	if !filepath.IsAbs(input.Path) {
		return errorResult("path must be absolute")
	}

	cleaned := filepath.Clean(input.Path)

	// Block ".." traversal
	for _, part := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if part == ".." {
			return errorResult("path traversal (..) is not allowed")
		}
	}

	// Block system paths
	if err := common.CheckDangerousPath(cleaned); err != nil {
		return errorResult(err.Error())
	}

	// Parse permission mode (default 0755)
	perm := os.FileMode(0755)
	if input.Mode != "" {
		parsed, err := strconv.ParseUint(input.Mode, 8, 32)
		if err != nil {
			return errorResult(fmt.Sprintf("invalid mode %q: must be octal (e.g. 0755, 0700)", input.Mode))
		}
		if parsed > 0777 {
			return errorResult(fmt.Sprintf("invalid mode %q: must be 0000-0777", input.Mode))
		}
		perm = os.FileMode(parsed)
	}

	// Check if already exists (Lstat: don't follow symlinks)
	if info, err := os.Lstat(cleaned); err == nil {
		// Block symlinks
		if info.Mode()&os.ModeSymlink != 0 && !common.GetAllowSymlinks() {
			return errorResult("path is a symlink and allow_symlinks is disabled")
		}
		if info.IsDir() {
			msg := fmt.Sprintf("directory already exists: %s", cleaned)
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: msg}},
			}, MkdirOutput{Result: msg}, nil
		}
		return errorResult(fmt.Sprintf("path exists but is not a directory: %s", cleaned))
	}

	// Default recursive to true (more intuitive for agents)
	recursive := input.Recursive == nil || *input.Recursive

	if common.FlexBool(input.DryRun) {
		mode := "recursive"
		if !recursive {
			mode = "single"
		}
		msg := fmt.Sprintf("[DRY RUN] would create directory (%s, mode %04o): %s", mode, perm, cleaned)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, MkdirOutput{Result: msg}, nil
	}

	var err error
	if recursive {
		err = os.MkdirAll(cleaned, perm)
	} else {
		err = os.Mkdir(cleaned, perm)
	}
	if err != nil {
		return errorResult(fmt.Sprintf("mkdir failed: %v", err))
	}

	// On Unix, MkdirAll/Mkdir respects umask, so explicitly chmod to ensure exact permission
	if err := os.Chmod(cleaned, perm); err != nil {
		// Directory was created but chmod failed — report but don't fail
		msg := fmt.Sprintf("OK: created directory %s (warning: chmod %04o failed: %v)", cleaned, perm, err)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, MkdirOutput{Result: msg}, nil
	}

	msg := fmt.Sprintf("OK: created directory %s (mode %04o)", cleaned, perm)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, MkdirOutput{Result: msg}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "mkdir",
		Description: `Create a directory. Creates parent directories by default (like mkdir -p).
Supports permission mode in octal (e.g. 0755, 0700) — applied on Unix/Linux.
Use dry_run=true to preview.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, MkdirOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, MkdirOutput{Result: msg}, nil
}
