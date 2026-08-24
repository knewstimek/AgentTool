package codegraph

import (
	"context"
	"fmt"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultCodeGraphMaxResults     = 500
	hardCodeGraphMaxResults        = 100000
	defaultCodeGraphMaxOutputChars = common.DefaultOutputChars
	hardCodeGraphMaxOutputChars    = common.HardOutputChars
)

// CodeGraphInput defines parameters for the codegraph tool.
type CodeGraphInput struct {
	Operation      string      `json:"operation" jsonschema:"Operation: index, find, callers, callees, symbols, methods, inherits, stats, importers, unused, call_tree,required"`
	Path           string      `json:"path,omitempty" jsonschema:"Project/file path. Relative paths use workspace/MCP root"`
	Roots          []string    `json:"roots,omitempty" jsonschema:"Optional source roots for one workspace index. When set, path stores the shared .codegraph.db and only these roots are scanned"`
	Name           string      `json:"name,omitempty" jsonschema:"Symbol name to search for (for find, callers, callees, methods, inherits, call_tree)"`
	Language       string      `json:"language,omitempty" jsonschema:"Language hint: cpp, python, go, csharp, rust, java. Default: auto-detect from file extension"`
	Workers        interface{} `json:"workers,omitempty" jsonschema:"Number of parallel parse workers for index operation. Default: 4. Higher = faster but more memory (~7MB per worker)"`
	Depth          interface{} `json:"depth,omitempty" jsonschema:"Max recursion depth for call_tree. Default: 3, Max: 10"`
	Direction      string      `json:"direction,omitempty" jsonschema:"Direction for call_tree: up (callers) or down (callees). Default: up"`
	Offset         int         `json:"offset,omitempty" jsonschema:"Zero-based result offset for symbols and callees paging. Default: 0"`
	MaxResults     int         `json:"max_results,omitempty" jsonschema:"Maximum results for symbols and callees. Default: 500, Max: 100000"`
	MaxOutputChars int         `json:"max_output_chars,omitempty" jsonschema:"Maximum total returned text characters for symbols and callees. Default: 32768, Max: 131072"`
}

// CodeGraphOutput holds the tool result.
type CodeGraphOutput struct {
	Result string `json:"result"`
}

var validOperations = map[string]bool{
	"index":     true,
	"find":      true,
	"callers":   true,
	"callees":   true,
	"symbols":   true,
	"methods":   true,
	"inherits":  true,
	"stats":     true,
	"importers": true,
	"unused":    true,
	"call_tree": true,
}

// Handle dispatches to the appropriate codegraph operation.
func Handle(ctx context.Context, req *mcp.CallToolRequest, input CodeGraphInput) (*mcp.CallToolResult, CodeGraphOutput, error) {
	op := strings.ToLower(strings.TrimSpace(input.Operation))
	allOps := "index, find, callers, callees, symbols, methods, inherits, stats, importers, unused, call_tree"
	if op == "" {
		return errorResult("operation is required (" + allOps + ")")
	}
	if !validOperations[op] {
		return errorResult(fmt.Sprintf("unknown operation: %s (available: %s)", op, allOps))
	}
	if err := normalizeCodeGraphLimits(&input); err != nil {
		return errorResult(err.Error())
	}
	if input.Path != "" {
		resolvedPath, err := common.ResolveRequestPath(ctx, req, input.Path)
		if err != nil {
			return errorResult(fmt.Sprintf("cannot resolve path: %v", err))
		}
		input.Path = resolvedPath
	}
	for index, root := range input.Roots {
		resolvedRoot, err := common.ResolveRequestPath(ctx, req, root)
		if err != nil {
			return errorResult(fmt.Sprintf("cannot resolve roots[%d]: %v", index, err))
		}
		input.Roots[index] = resolvedRoot
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
	case "stats":
		result, err = opStats(input)
	case "importers":
		result, err = opImporters(input)
	case "unused":
		result, err = opUnused(input)
	case "call_tree":
		result, err = opCallTree(input)
	}

	if err != nil {
		return errorResult(err.Error())
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, CodeGraphOutput{Result: result}, nil
}

func normalizeCodeGraphLimits(input *CodeGraphInput) error {
	if input.Offset < 0 {
		return fmt.Errorf("offset must be non-negative")
	}
	if input.MaxResults <= 0 {
		input.MaxResults = defaultCodeGraphMaxResults
	}
	if input.MaxResults > hardCodeGraphMaxResults {
		return fmt.Errorf("max_results must be at most %d", hardCodeGraphMaxResults)
	}
	if input.MaxOutputChars <= 0 {
		input.MaxOutputChars = defaultCodeGraphMaxOutputChars
	}
	if input.MaxOutputChars > hardCodeGraphMaxOutputChars {
		return fmt.Errorf("max_output_chars must be at most %d", hardCodeGraphMaxOutputChars)
	}
	return nil
}

// Register adds the codegraph tool to the MCP server.
func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "codegraph",
		Description: `Fully embedded semantic code graph and symbol lookup tool.
Parses Go with the standard library AST and other languages with lazy compressed
tree-sitter WASM. No compiler, language server, or external binary is required.
Stores stable declaration/definition identities, return/receiver data flow,
aliases, transitive includes, build conditions, calibrated candidate evidence,
dynamic dispatch, and calls in a local SQLite index (.codegraph.db).
Operations:
  index(path, roots?) - Build/update one project or a multi-root workspace index.
  find(name) - Find symbol definitions by name (function, class, method).
  callers(name) - Find all callers of a function/method.
  callees(name) - Find all functions/methods called by a function.
  symbols(path) - List all symbols in a file (no index needed). Supports offset/max_results paging.
  methods(name) - List all methods of a class.
  inherits(name) - Show inheritance hierarchy of a class.
  stats(path) - Project index statistics (files, classes, functions, calls).
  importers(path, name) - Find files that import/include a given file.
  unused(path) - Find symbols defined but never called (dead code).
  call_tree(name, depth, direction) - Recursive call hierarchy (up=callers, down=callees).
Supports: C/C++, Python, Go, C#, Rust, Java.
Index is stored at project root as .codegraph.db (add to .gitignore).
Respects .gitignore (including nested) and skips non-source dirs (venv, vendor, third_party, etc.).
No LLM calls, no embeddings -- pure data lookup, zero token cost.
Tip: Run index once at the start of a session, then use find/callers/call_tree to navigate.
Large symbols/callees results are bounded by max_output_chars and include the next offset.
Re-run index after bulk edits to update changed files (incremental, fast).
Powered by Go's standard parser and tree-sitter (MIT) via wazero.`,
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
