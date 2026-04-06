package checksum

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ChecksumInput struct {
	FilePath  string `json:"file_path,omitempty" jsonschema:"Absolute path to the file"`
	Path      string `json:"path,omitempty" jsonschema:"Alias for file_path"`
	Algorithm string `json:"algorithm,omitempty" jsonschema:"Hash algorithm: md5, sha1, sha256 (default sha256)"`
}

type ChecksumOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input ChecksumInput) (*mcp.CallToolResult, ChecksumOutput, error) {
	if input.FilePath == "" {
		input.FilePath = input.Path
	}
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	if !filepath.IsAbs(input.FilePath) {
		return errorResult("file_path must be an absolute path")
	}

	algo := strings.ToLower(strings.TrimSpace(input.Algorithm))
	if algo == "" {
		algo = "sha256"
	}

	var h hash.Hash
	switch algo {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	default:
		return errorResult(fmt.Sprintf("unsupported algorithm: %s (supported: md5, sha1, sha256)", algo))
	}

	// Symlink check
	if !common.GetAllowSymlinks() {
		if lfi, err := os.Lstat(input.FilePath); err == nil && lfi.Mode()&os.ModeSymlink != 0 {
			return errorResult("symlinks are not allowed (see set_config allow_symlinks)")
		}
	}

	fi, err := os.Stat(input.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("file not found: %s", input.FilePath))
		}
		return errorResult(fmt.Sprintf("cannot access file: %v", err))
	}
	if fi.IsDir() {
		return errorResult("path is a directory, not a file")
	}

	f, err := os.Open(input.FilePath)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot open file: %v", err))
	}
	defer f.Close()

	if _, err := io.Copy(h, f); err != nil {
		return errorResult(fmt.Sprintf("failed to read file: %v", err))
	}

	msg := fmt.Sprintf("%x  %s  (%s)", h.Sum(nil), filepath.Base(input.FilePath), algo)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, ChecksumOutput{Result: msg}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "checksum",
		Description: `Computes a hash checksum of a file.
Reads the file as raw bytes (no encoding conversion).
Supported algorithms: md5, sha1, sha256 (default).`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, ChecksumOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, ChecksumOutput{Result: msg}, nil
}
