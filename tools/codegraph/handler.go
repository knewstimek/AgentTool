package codegraph

import (
	"context"
	"fmt"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// CodeGraphInput defines parameters for the codegraph tool.
type CodeGraphInput struct {
	Operation string `json:"operation" jsonschema:"Operation: index, find, callers, callees, symbols, methods, inherits,required"`
	Path      string `json:"path,omitempty" jsonschema:"Project directory path (for index) or file path (for symbols)"`
	Name      string `json:"name,omitempty" jsonschema:"Symbol name to search for (for find, callers, callees, methods, inherits)"`
	Language  string `json:"language,omitempty" jsonschema:"Language hint: cpp, python, go, csharp, rust, java. Default: auto-detect from file extension"`
	Workers   int    `json:"workers,omitempty" jsonschema:"Number of parallel parse workers for index operation. Default: 4. Higher = faster but more memory (~7MB per worker)"`
}

// CodeGraphOutput holds the tool result.
type CodeGraphOutput struct {
	Result string `json:"result"`
}

var validOperations = map[string]bool{
	"index":    true,
	"find":     true,
	"callers":  true,
	"callees":  true,
	"symbols":  true,
	"methods":  true,
	"inherits": true,
}

// Handle dispatches to the appropriate codegraph operation.
func Handle(ctx context.Context, req *mcp.CallToolRequest, input CodeGraphInput) (*mcp.CallToolResult, CodeGraphOutput, error) {
	op := strings.ToLower(strings.TrimSpace(input.Operation))
	allOps := "index, find, callers, callees, symbols, methods, inherits"
	if op == "" {
		return errorResult("operation is required (" + allOps + ")")
	}
	if !validOperations[op] {
		return errorResult(fmt.Sprintf("unknown operation: %s (available: %s)", op, allOps))
	}

	var result string
	var err error

	switch op {
	case "index":
		result, err = opIndex(input)
	case "find":
		result, err = opFind(input)
	case "callers":
		result, err = opCallers(input)
	case "callees":
		result, err = opCallees(input)
	case "symbols":
		result, err = opSymbols(input)
	case "methods":
		result, err = opMethods(input)
	case "inherits":
		result, err = opInherits(input)
	}

	if err != nil {
		return errorResult(err.Error())
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, CodeGraphOutput{Result: result}, nil
}

// Register adds the codegraph tool to the MCP server.
func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "codegraph",
		Description: `AST-based code indexing and symbol lookup tool.
Parses source code with tree-sitter (via WASM, no external dependencies) and stores
symbols/relationships in a local SQLite index (.codegraph.db).
Operations:
  index(path) - Build or update the code index for a project directory.
  find(name) - Find symbol definitions by name (function, class, method).
  callers(name) - Find all callers of a function/method.
  callees(name) - Find all functions/methods called by a function.
  symbols(path) - List all symbols in a file.
  methods(name) - List all methods of a class.
  inherits(name) - Show inheritance hierarchy of a class.
Supports: C/C++, Python, Go, C#, Rust, Java.
Index is stored at project root as .codegraph.db (add to .gitignore).
No LLM calls, no embeddings -- pure data lookup, zero token cost.
Tip: Run index once at the start of a session, then use find/callers/methods to navigate.
Re-run index after bulk edits to update changed files (incremental, fast).
symbols works without an index (parses on-the-fly, good for single files).
Powered by tree-sitter (MIT) via wazero (pure Go WASM runtime).`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, CodeGraphOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, CodeGraphOutput{Result: msg}, nil
}

func successResult(msg string) (*mcp.CallToolResult, CodeGraphOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, CodeGraphOutput{Result: msg}, nil
}
