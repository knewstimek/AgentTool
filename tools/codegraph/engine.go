package codegraph

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed wasm/tree-sitter-cpp.wasm
var cppWasm []byte

// engine holds the wazero runtime and tree-sitter WASM module instance.
// It is lazily initialized on first use and reused across calls.
// ParseCPP is serialized with mu because WASM linear memory is shared.
type engine struct {
	mu      sync.Mutex
	runtime wazero.Runtime
	mod     api.Module
	langPtr uint64 // pointer to TSLanguage in WASM memory
}

var (
	engineOnce sync.Once
	engineInst *engine
	engineErr  error
)

// getEngine returns the singleton engine, initializing it on first call.
func getEngine() (*engine, error) {
	engineOnce.Do(func() {
		engineInst, engineErr = newEngine()
	})
	return engineInst, engineErr
}

func newEngine() (*engine, error) {
	ctx := context.Background()

	r := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	mod, err := r.Instantiate(ctx, cppWasm)
	if err != nil {
		r.Close(ctx)
		return nil, fmt.Errorf("tree-sitter WASM init failed: %w", err)
	}

	// Get C++ language pointer
	langRes, err := mod.ExportedFunction("get_language_cpp").Call(ctx)
	if err != nil {
		r.Close(ctx)
		return nil, fmt.Errorf("get_language_cpp failed: %w", err)
	}

	return &engine{
		runtime: r,
		mod:     mod,
		langPtr: langRes[0],
	}, nil
}

// Symbol represents an extracted code symbol.
type Symbol struct {
	Capture  string // "class", "function", "call", "callee"
	NodeType string // tree-sitter node type
	Name     string // symbol name
	Line     int    // 1-based line number
	Col      int    // 0-based column
	Parent   string // parent node type
	Scope    string // enclosing class/namespace name
}

// ParseResult holds parsed symbols from a source file.
type ParseResult struct {
	Classes   []Symbol
	Functions []Symbol
	Calls     []Symbol
}

// tree-sitter query patterns (from code-graph-rag, MIT license)
const classQueryCPP = `
(class_specifier) @class
(struct_specifier) @class
(union_specifier) @class
(enum_specifier) @class
(template_declaration (class_specifier)) @class
(template_declaration (struct_specifier)) @class
`

const functionQueryCPP = `
(function_definition) @function
(declaration
  declarator: (function_declarator)) @function
(template_declaration (function_definition)) @function
`

const callQueryCPP = `
(call_expression
  function: (_) @callee) @call
`

// ParseCPP parses C++ source code and extracts symbols.
// Serialized with mutex because WASM linear memory is shared across calls.
func (e *engine) ParseCPP(source string) (*ParseResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	const maxSourceSize = 10 * 1024 * 1024
	if len(source) > maxSourceSize {
		return nil, fmt.Errorf("source too large (%d bytes, max %d)", len(source), maxSourceSize)
	}

	ctx := context.Background()
	mem := e.mod.Memory()

	// Allocate and write source to WASM memory
	srcPtr, err := e.allocString(ctx, source)
	if err != nil {
		return nil, err
	}
	defer e.free(ctx, srcPtr)

	// Create parser
	parserRes, err := e.mod.ExportedFunction("ts_parser_new").Call(ctx)
	if err != nil {
		return nil, fmt.Errorf("ts_parser_new: %w", err)
	}
	parserPtr := parserRes[0]
	defer e.mod.ExportedFunction("ts_parser_delete").Call(ctx, parserPtr)

	// Set language
	setRes, err := e.mod.ExportedFunction("ts_parser_set_language").Call(ctx, parserPtr, e.langPtr)
	if err != nil || setRes[0] == 0 {
		return nil, fmt.Errorf("ts_parser_set_language failed")
	}

	// Parse
	treeRes, err := e.mod.ExportedFunction("ts_parser_parse_string").Call(ctx, parserPtr, 0, uint64(srcPtr), uint64(len(source)))
	if err != nil {
		return nil, fmt.Errorf("ts_parser_parse_string: %w", err)
	}
	treePtr := treeRes[0]
	if treePtr == 0 {
		return nil, fmt.Errorf("parse returned null tree")
	}
	defer e.mod.ExportedFunction("ts_tree_delete").Call(ctx, treePtr)

	// Get root node (sret: first param is output pointer)
	nodePtr, err := e.allocBuf(ctx, 32)
	if err != nil {
		return nil, err
	}
	defer e.free(ctx, nodePtr)
	e.mod.ExportedFunction("ts_tree_root_node").Call(ctx, uint64(nodePtr), treePtr)

	// Output buffer for extract_symbols
	outBufSize := uint32(131072) // 128KB
	outPtr, err := e.allocBuf(ctx, outBufSize)
	if err != nil {
		return nil, err
	}
	defer e.free(ctx, outPtr)

	extractFn := e.mod.ExportedFunction("extract_symbols")
	if extractFn == nil {
		return nil, fmt.Errorf("extract_symbols not exported")
	}

	// Helper to run a query and parse results
	runQuery := func(query string) ([]Symbol, error) {
		qPtr, err := e.allocString(ctx, query)
		if err != nil {
			return nil, err
		}
		defer e.free(ctx, qPtr)

		// Clear output buffer
		zeros := make([]byte, outBufSize)
		mem.Write(outPtr, zeros)

		result, err := extractFn.Call(ctx,
			e.langPtr,
			uint64(nodePtr),
			uint64(qPtr), uint64(len(query)),
			uint64(srcPtr),
			uint64(outPtr), uint64(outBufSize),
		)
		if err != nil {
			return nil, err
		}

		resultLen := uint32(result[0])
		if resultLen == 0 {
			return nil, nil
		}
		if resultLen > outBufSize {
			resultLen = outBufSize
		}

		outBytes, ok := mem.Read(outPtr, resultLen)
		if !ok {
			return nil, fmt.Errorf("failed to read WASM output buffer")
		}
		return parseSymbolOutput(string(outBytes)), nil
	}

	result := &ParseResult{}

	result.Classes, err = runQuery(classQueryCPP)
	if err != nil {
		return nil, fmt.Errorf("class query: %w", err)
	}

	result.Functions, err = runQuery(functionQueryCPP)
	if err != nil {
		return nil, fmt.Errorf("function query: %w", err)
	}

	result.Calls, err = runQuery(callQueryCPP)
	if err != nil {
		return nil, fmt.Errorf("call query: %w", err)
	}

	return result, nil
}

// parseSymbolOutput parses the pipe-delimited output from extract_symbols.
// Format: capture|node_type|name|line|col|parent_type|scope
func parseSymbolOutput(output string) []Symbol {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var symbols []Symbol
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 7)
		if len(parts) < 6 {
			continue
		}
		sym := Symbol{
			Capture:  parts[0],
			NodeType: parts[1],
			Name:     parts[2],
			Parent:   parts[5],
		}
		fmt.Sscanf(parts[3], "%d", &sym.Line)
		fmt.Sscanf(parts[4], "%d", &sym.Col)
		if len(parts) >= 7 {
			sym.Scope = parts[6]
		}
		symbols = append(symbols, sym)
	}
	return symbols
}

// allocString writes a null-terminated string to WASM memory.
func (e *engine) allocString(ctx context.Context, s string) (uint32, error) {
	b := []byte(s)
	res, err := e.mod.ExportedFunction("alloc_string").Call(ctx, uint64(len(b)+1))
	if err != nil {
		return 0, err
	}
	ptr := uint32(res[0])
	if ptr == 0 {
		return 0, fmt.Errorf("WASM alloc failed (requested %d bytes)", len(b)+1)
	}
	e.mod.Memory().Write(ptr, b)
	e.mod.Memory().WriteByte(ptr+uint32(len(b)), 0)
	return ptr, nil
}

// allocBuf allocates zeroed memory in WASM.
func (e *engine) allocBuf(ctx context.Context, size uint32) (uint32, error) {
	res, err := e.mod.ExportedFunction("alloc_buf").Call(ctx, uint64(size))
	if err != nil {
		return 0, err
	}
	ptr := uint32(res[0])
	if ptr == 0 {
		return 0, fmt.Errorf("WASM alloc failed (requested %d bytes)", size)
	}
	return ptr, nil
}

// free releases WASM memory.
func (e *engine) free(ctx context.Context, ptr uint32) {
	e.mod.ExportedFunction("ts_free").Call(ctx, uint64(ptr))
}
