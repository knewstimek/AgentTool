package analyze

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// AnalyzeInput defines parameters for the static binary analysis tool.
type AnalyzeInput struct {
	Operation string `json:"operation" jsonschema:"Operation: disassemble, pe_info, strings, hexdump,required"`
	FilePath  string `json:"file_path" jsonschema:"Absolute path to the binary file,required"`

	// disassemble parameters
	Offset   int    `json:"offset,omitempty" jsonschema:"Byte offset to start from. Default: 0"`
	Count    int    `json:"count,omitempty" jsonschema:"Number of instructions (disassemble). Default: 50, Max: 200"`
	Mode     int    `json:"mode,omitempty" jsonschema:"CPU mode: 32 or 64. Default: 64"`
	BaseAddr string `json:"base_addr,omitempty" jsonschema:"Base address for display (hex string, e.g. '0x140001000'). Default: 0x0"`

	// strings parameters
	MinLength  int    `json:"min_length,omitempty" jsonschema:"Minimum string length for strings operation. Default: 4"`
	MaxResults int    `json:"max_results,omitempty" jsonschema:"Maximum number of results for strings. Default: 500, Max: 2000"`
	Encoding   string `json:"encoding,omitempty" jsonschema:"String encoding to search for: ascii (default) or utf8"`

	// hexdump parameters
	Length int `json:"length,omitempty" jsonschema:"Number of bytes for hexdump. Default: 256, Max: 4096"`

	// pe_info parameters
	Section string `json:"section,omitempty" jsonschema:"Filter by section name (e.g. '.text', '.rdata'). Empty = show all"`
	RVA     string `json:"rva,omitempty" jsonschema:"RVA to convert to file offset (hex string, e.g. '0x36A20'). For pe_info only"`
}

// AnalyzeOutput holds the tool result.
type AnalyzeOutput struct {
	Result string `json:"result"`
}

var validOperations = map[string]bool{
	"disassemble": true,
	"pe_info":     true,
	"strings":    true,
	"hexdump":    true,
}

// Handle dispatches to the appropriate operation.
func Handle(ctx context.Context, req *mcp.CallToolRequest, input AnalyzeInput) (*mcp.CallToolResult, AnalyzeOutput, error) {
	op := strings.ToLower(strings.TrimSpace(input.Operation))
	if op == "" {
		return errorResult("operation is required (disassemble, pe_info, strings, hexdump)")
	}
	if !validOperations[op] {
		return errorResult(fmt.Sprintf("unknown operation: %s (available: disassemble, pe_info, strings, hexdump)", op))
	}

	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	input.FilePath = filepath.Clean(input.FilePath)
	if !filepath.IsAbs(input.FilePath) {
		return errorResult("file_path must be an absolute path")
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

	// File size check — use configured max (default 50MB)
	maxSize := int64(common.GetMaxFileSize())
	if fi.Size() > maxSize {
		return errorResult(fmt.Sprintf("file too large: %d bytes (max %d MB, change with set_config max_file_size_mb)",
			fi.Size(), maxSize/(1024*1024)))
	}

	var result string
	switch op {
	case "disassemble":
		result, err = opDisassemble(input)
	case "pe_info":
		result, err = opPEInfo(input)
	case "strings":
		result, err = opStrings(input)
	case "hexdump":
		result, err = opHexdump(input)
	}

	if err != nil {
		return errorResult(err.Error())
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, AnalyzeOutput{Result: result}, nil
}

// Register adds the analyze tool to the MCP server.
func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "analyze",
		Description: `Static binary analysis tool for reverse engineering and debugging.
Operations: disassemble (x86/x64 disassembly), pe_info (PE header/sections/imports/exports),
strings (extract printable strings from binary), hexdump (hex+ASCII view).
Pure Go implementation — no external tools needed. Supports x86 (32-bit) and x64 (64-bit).
For runtime debugging, use the debug tool instead.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, AnalyzeOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, AnalyzeOutput{Result: msg}, nil
}

func successResult(msg string) (*mcp.CallToolResult, AnalyzeOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, AnalyzeOutput{Result: msg}, nil
}
