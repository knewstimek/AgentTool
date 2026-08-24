package common

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RequestWorkspace returns the explicit configured workspace, then the first
// local MCP root advertised by the client, then the server process directory.
// This makes relative paths follow the agent's project instead of the often
// unrelated directory from which the MCP server happened to be launched.
func RequestWorkspace(ctx context.Context, req *mcp.CallToolRequest) string {
	if configured := GetWorkspace(); configured != "" {
		return configured
	}
	if req != nil && req.Session != nil {
		params := req.Session.InitializeParams()
		if params != nil && params.Capabilities != nil && params.Capabilities.RootsV2 != nil {
			if result, err := req.Session.ListRoots(ctx, nil); err == nil {
				for _, root := range result.Roots {
					if path, err := FileURIPath(root.URI); err == nil && path != "" {
						return path
					}
				}
			}
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		return cwd
	}
	return "."
}

// ResolveRequestPath resolves a local relative path against RequestWorkspace.
func ResolveRequestPath(ctx context.Context, req *mcp.CallToolRequest, path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("path is empty")
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	return filepath.Abs(filepath.Join(RequestWorkspace(ctx, req), path))
}

// FileURIPath converts an MCP file:// root URI into a native filesystem path.
func FileURIPath(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	if u.Scheme != "file" {
		return "", fmt.Errorf("unsupported root URI scheme %q", u.Scheme)
	}
	path, err := url.PathUnescape(u.EscapedPath())
	if err != nil {
		return "", err
	}
	if u.Host != "" && u.Host != "localhost" {
		path = "//" + u.Host + path
	}
	if runtime.GOOS == "windows" && len(path) >= 3 && path[0] == '/' && path[2] == ':' {
		path = path[1:]
	}
	return filepath.Clean(filepath.FromSlash(path)), nil
}
