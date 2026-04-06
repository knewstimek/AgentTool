package rename

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type RenameInput struct {
	OldPath string `json:"old_path" jsonschema:"Absolute path to the file or directory to rename"`
	NewPath string `json:"new_path" jsonschema:"Absolute path for the new name/location"`
	DryRun  interface{} `json:"dry_run,omitempty" jsonschema:"Preview rename without actually moving the file: true or false. Default: false"`
}

type RenameOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input RenameInput) (*mcp.CallToolResult, RenameOutput, error) {
	if input.OldPath == "" || input.NewPath == "" {
		return errorResult("both old_path and new_path are required")
	}
	if !filepath.IsAbs(input.OldPath) || !filepath.IsAbs(input.NewPath) {
		return errorResult("both paths must be absolute")
	}

	oldCleaned := filepath.Clean(input.OldPath)
	newCleaned := filepath.Clean(input.NewPath)

	// Block ".." traversal
	for _, p := range []string{oldCleaned, newCleaned} {
		for _, part := range strings.Split(filepath.ToSlash(p), "/") {
			if part == ".." {
				return errorResult("path traversal (..) is not allowed")
			}
		}
	}

	// Check if paths are the same
	if oldCleaned == newCleaned {
		return errorResult("old_path and new_path are the same")
	}

	// Block system paths (both source and destination)
	for _, p := range []string{oldCleaned, newCleaned} {
		if err := common.CheckWindowsReserved(p); err != nil {
			return errorResult(err.Error())
		}
		if err := common.CheckDangerousPath(p); err != nil {
			return errorResult(err.Error())
		}
	}

	// Check if source exists (Lstat: don't follow symlinks)
	oldInfo, err := os.Lstat(oldCleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("source not found: %s", oldCleaned))
		}
		return errorResult(fmt.Sprintf("cannot access source: %v", err))
	}

	// Block symlinks when not allowed
	if oldInfo.Mode()&os.ModeSymlink != 0 && !common.GetAllowSymlinks() {
		return errorResult("source is a symlink and allow_symlinks is disabled")
	}

	// Check if destination already exists
	if _, err := os.Lstat(newCleaned); err == nil {
		return errorResult(fmt.Sprintf("destination already exists: %s", newCleaned))
	}

	// Check if destination directory exists
	newDir := filepath.Dir(newCleaned)
	if _, err := os.Stat(newDir); os.IsNotExist(err) {
		return errorResult(fmt.Sprintf("destination directory does not exist: %s", newDir))
	}

	kind := "file"
	if oldInfo.IsDir() {
		kind = "directory"
	}

	// dry_run
	if common.FlexBool(input.DryRun) {
		msg := fmt.Sprintf("[DRY RUN] would rename %s: %s → %s", kind, oldCleaned, newCleaned)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, RenameOutput{Result: msg}, nil
	}

	// Perform actual rename (os.Rename is atomic)
	if err := os.Rename(oldCleaned, newCleaned); err != nil {
		return errorResult(fmt.Sprintf("rename failed: %v", err))
	}

	msg := fmt.Sprintf("OK: renamed %s: %s → %s", kind, oldCleaned, newCleaned)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, RenameOutput{Result: msg}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name:        "rename",
		Description: "Renames or moves a file/directory. Atomic operation via os.Rename. Use dry_run=true to preview.",
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, RenameOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, RenameOutput{Result: msg}, nil
}
