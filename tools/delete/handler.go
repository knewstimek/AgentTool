package delete

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type DeleteInput struct {
	FilePath string `json:"file_path,omitempty" jsonschema:"Absolute path to the file to delete"`
	Path     string `json:"path,omitempty" jsonschema:"Alias for file_path"`
	DryRun   interface{} `json:"dry_run,omitempty" jsonschema:"Preview deletion without actually removing the file: true or false. Default: false"`
}

type DeleteOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input DeleteInput) (*mcp.CallToolResult, DeleteOutput, error) {
	if input.FilePath == "" {
		input.FilePath = input.Path
	}
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	if !filepath.IsAbs(input.FilePath) {
		return errorResult("file_path must be an absolute path")
	}

	// Normalize path
	cleaned := filepath.Clean(input.FilePath)

	// [FIX #4] Check for ".." per path component (avoid false positives from consecutive dots in filenames)
	for _, part := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if part == ".." {
			return errorResult("path traversal (..) is not allowed")
		}
	}

	// [FIX #2] Block Windows reserved device names
	if runtime.GOOS == "windows" {
		if err := checkWindowsReserved(cleaned); err != nil {
			return errorResult(err.Error())
		}
	}

	// [FIX #3] Block critical system paths
	if err := checkDangerousPath(cleaned); err != nil {
		return errorResult(err.Error())
	}

	// Check file info
	info, err := os.Lstat(cleaned) // Lstat: does not follow symlinks
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("file not found: %s", cleaned))
		}
		return errorResult(fmt.Sprintf("cannot access file: %v", err))
	}

	// Directory deletion is not allowed
	if info.IsDir() {
		return errorResult("directory deletion is not allowed. Only individual files can be deleted")
	}

	// Symlink deletion is not allowed
	if info.Mode()&os.ModeSymlink != 0 {
		return errorResult("symlink deletion is not allowed for safety")
	}

	// dry_run mode
	if common.FlexBool(input.DryRun) {
		msg := fmt.Sprintf("[DRY RUN] would delete: %s (%d bytes)", cleaned, info.Size())
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, DeleteOutput{Result: msg}, nil
	}

	// [FIX #1] TOCTOU mitigation: re-check file state right before deletion
	info2, err := os.Lstat(cleaned)
	if err != nil {
		return errorResult(fmt.Sprintf("pre-delete check failed: %v", err))
	}
	if info2.IsDir() || info2.Mode()&os.ModeSymlink != 0 {
		return errorResult("file type changed before deletion (possible race condition)")
	}

	// Perform actual deletion
	if err := os.Remove(cleaned); err != nil {
		return errorResult(fmt.Sprintf("delete failed: %v", err))
	}

	msg := fmt.Sprintf("OK: deleted %s (%d bytes)", cleaned, info.Size())
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, DeleteOutput{Result: msg}, nil
}

// checkWindowsReserved blocks Windows reserved device names and ADS paths.
func checkWindowsReserved(cleaned string) error {
	// Block ADS (Alternate Data Stream): another colon after the drive letter colon indicates ADS
	drive := filepath.VolumeName(cleaned)
	rest := cleaned[len(drive):]
	if strings.Contains(rest, ":") {
		return fmt.Errorf("alternate data stream (ADS) paths are not allowed")
	}

	// Block reserved device names
	base := filepath.Base(cleaned)
	upperBase := strings.ToUpper(strings.TrimSuffix(base, filepath.Ext(base)))
	reserved := []string{
		"CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
	}
	for _, r := range reserved {
		if upperBase == r {
			return fmt.Errorf("deletion of Windows reserved device name is not allowed: %s", base)
		}
	}
	return nil
}

// checkDangerousPath blocks file deletion in critical system paths.
func checkDangerousPath(cleaned string) error {
	normalized := strings.ToLower(filepath.ToSlash(cleaned))

	var blocked []string
	if runtime.GOOS == "windows" {
		winDir := os.Getenv("WINDIR")
		if winDir == "" {
			winDir = `C:\Windows`
		}
		blocked = []string{
			strings.ToLower(filepath.ToSlash(winDir)) + "/",
		}
	} else {
		blocked = []string{
			"/etc/", "/boot/", "/sbin/", "/usr/sbin/",
			"/proc/", "/sys/", "/dev/",
			"/var/run/", "/run/",           // runtime sockets/PIDs
			"/usr/lib/systemd/",            // systemd units
			"/lib/systemd/",                // CentOS/RHEL systemd
			"/usr/lib64/",                  // RHEL/CentOS libraries
			"/lib64/",                      // RHEL/CentOS libraries
			"/lib/", "/usr/lib/",           // system libraries
			"/root/",                       // root home
		}
	}

	for _, prefix := range blocked {
		if strings.HasPrefix(normalized, prefix) {
			return fmt.Errorf("deletion of system files is not allowed: %s", cleaned)
		}
	}
	return nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name:        "delete",
		Description: "Deletes a single file. Safety: no directory/symlink deletion, no path traversal, no system files, TOCTOU protection. Use dry_run=true to preview.",
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, DeleteOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, DeleteOutput{Result: msg}, nil
}
