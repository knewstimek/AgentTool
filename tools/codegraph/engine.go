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

//go:embed wasm/tree-sitter-python.wasm
var pythonWasm []byte

//go:embed wasm/tree-sitter-go.wasm
var goWasm []byte

//go:embed wasm/tree-sitter-c_sharp.wasm
var csharpWasm []byte

//go:embed wasm/tree-sitter-rust.wasm
var rustWasm []byte

//go:embed wasm/tree-sitter-java.wasm
var javaWasm []byte

// engine holds a wazero runtime and tree-sitter WASM module for one language.
// Parse is serialized with mu because WASM linear memory is shared.
type engine struct {
	mu      sync.Mutex
	runtime wazero.Runtime
	mod     api.Module
	langPtr uint64
	lang    string // language identifier
	queries langQueries
}

// langQueries holds tree-sitter query patterns for a language.
type langQueries struct {
	classes   string
	functions string
	calls     string
}

// engines holds lazily-initialized per-language engines.
var engines = struct {
	mu   sync.Mutex
	byLang map[string]*engine
}{byLang: make(map[string]*engine)}

// getEngine returns the engine for a language, initializing it on first call.
func getEngine(lang string) (*engine, error) {
	engines.mu.Lock()
	defer engines.mu.Unlock()

	if e, ok := engines.byLang[lang]; ok {
		return e, nil
	}

	e, err := newEngine(lang)
	if err != nil {
		return nil, err
	}
	engines.byLang[lang] = e
	return e, nil
}

func newEngine(lang string) (*engine, error) {
	wasmBytes, queries, err := langConfig(lang)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	mod, err := r.Instantiate(ctx, wasmBytes)
	if err != nil {
		r.Close(ctx)
		return nil, fmt.Errorf("tree-sitter WASM init (%s): %w", lang, err)
	}

	// All language WASMs export get_language (or get_language_cpp for cpp)
	getFn := mod.ExportedFunction("get_language")
	if getFn == nil {
		getFn = mod.ExportedFunction("get_language_cpp")
	}
	if getFn == nil {
		r.Close(ctx)
		return nil, fmt.Errorf("get_language not exported (%s)", lang)
	}

	langRes, err := getFn.Call(ctx)
	if err != nil {
		r.Close(ctx)
		return nil, fmt.Errorf("get_language failed (%s): %w", lang, err)
	}

	return &engine{
		runtime: r,
		mod:     mod,
		langPtr: langRes[0],
		lang:    lang,
		queries: queries,
	}, nil
}

// langConfig returns WASM bytes and query patterns for a language.
func langConfig(lang string) ([]byte, langQueries, error) {
	switch lang {
	case "cpp":
		return cppWasm, langQueries{
			classes:   queryCPPClasses,
			functions: queryCPPFunctions,
			calls:     queryCPPCalls,
		}, nil
	case "python":
		return pythonWasm, langQueries{
			classes:   queryPythonClasses,
			functions: queryPythonFunctions,
			calls:     queryPythonCalls,
		}, nil
	case "go":
		return goWasm, langQueries{
			classes:   queryGoTypes,
			functions: queryGoFunctions,
			calls:     queryGoCalls,
		}, nil
	case "csharp":
		return csharpWasm, langQueries{
			classes:   queryCSharpClasses,
			functions: queryCSharpFunctions,
			calls:     queryCSharpCalls,
		}, nil
	case "rust":
		return rustWasm, langQueries{
			classes:   queryRustTypes,
			functions: queryRustFunctions,
			calls:     queryRustCalls,
		}, nil
	case "java":
		return javaWasm, langQueries{
			classes:   queryJavaClasses,
			functions: queryJavaFunctions,
			calls:     queryJavaCalls,
		}, nil
	default:
		return nil, langQueries{}, fmt.Errorf("unsupported language: %s (available: cpp, python, go, csharp, rust, java)", lang)
	}
}

// Symbol represents an extracted code symbol.
type Symbol struct {
	Capture  string
	NodeType string
	Name     string
	Line     int
	Col      int
	Parent   string
	Scope    string
}

// Inheritance represents a class -> parent relationship.
type Inheritance struct {
	ClassName  string
	ParentName string
	Line       int
}

// ParseResult holds parsed symbols from a source file.
type ParseResult struct {
	Classes      []Symbol
	Functions    []Symbol
	Calls        []Symbol
	Inheritance  []Inheritance
}

// ---- Tree-sitter query patterns per language ----
// C++ queries from code-graph-rag (vitali87, MIT license)

const queryCPPClasses = `
(class_specifier) @class
(struct_specifier) @class
(union_specifier) @class
(enum_specifier) @class
(template_declaration (class_specifier)) @class
(template_declaration (struct_specifier)) @class
`

const queryCPPFunctions = `
(function_definition) @function
(declaration
  declarator: (function_declarator)) @function
(template_declaration (function_definition)) @function
`

const queryCPPCalls = `
(call_expression
  function: (_) @callee) @call
`

// Python query patterns
const queryPythonClasses = `
(class_definition) @class
`

const queryPythonFunctions = `
(function_definition) @function
(decorated_definition (function_definition)) @function
`

const queryPythonCalls = `
(call
  function: (_) @callee) @call
`

// Go query patterns
const queryGoTypes = `
(type_declaration (type_spec)) @class
`

const queryGoFunctions = `
(function_declaration) @function
(method_declaration) @function
`

const queryGoCalls = `
(call_expression
  function: (_) @callee) @call
`

// C# query patterns
const queryCSharpClasses = `
(class_declaration) @class
(struct_declaration) @class
(interface_declaration) @class
(enum_declaration) @class
`

const queryCSharpFunctions = `
(method_declaration) @function
(constructor_declaration) @function
`

const queryCSharpCalls = `
(invocation_expression
  function: (_) @callee) @call
`

// Rust query patterns (from code-graph-rag, MIT license)
const queryRustTypes = `
(struct_item) @class
(enum_item) @class
(union_item) @class
(trait_item) @class
(type_item) @class
(impl_item) @class
`

const queryRustFunctions = `
(function_item) @function
(function_signature_item) @function
`

const queryRustCalls = `
(call_expression
  function: (_) @callee) @call
(macro_invocation
  macro: (identifier) @callee) @call
`

// Java query patterns (from code-graph-rag, MIT license)
const queryJavaClasses = `
(class_declaration) @class
(interface_declaration) @class
(enum_declaration) @class
(record_declaration) @class
`

const queryJavaFunctions = `
(method_declaration) @function
(constructor_declaration) @function
`

const queryJavaCalls = `
(method_invocation
  name: (identifier) @callee) @call
(object_creation_expression
  type: (type_identifier) @callee) @call
`

// Parse parses source code and extracts symbols using the engine's language.
func (e *engine) Parse(source string) (*ParseResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	const maxSourceSize = 10 * 1024 * 1024
	if len(source) > maxSourceSize {
		return nil, fmt.Errorf("source too large (%d bytes, max %d)", len(source), maxSourceSize)
	}

	ctx := context.Background()
	mem := e.mod.Memory()

	srcPtr, err := e.allocString(ctx, source)
	if err != nil {
		return nil, err
	}
	defer e.free(ctx, srcPtr)

	parserRes, err := e.mod.ExportedFunction("ts_parser_new").Call(ctx)
	if err != nil {
		return nil, fmt.Errorf("ts_parser_new: %w", err)
	}
	parserPtr := parserRes[0]
	defer e.mod.ExportedFunction("ts_parser_delete").Call(ctx, parserPtr)

	setRes, err := e.mod.ExportedFunction("ts_parser_set_language").Call(ctx, parserPtr, e.langPtr)
	if err != nil || setRes[0] == 0 {
		return nil, fmt.Errorf("ts_parser_set_language failed")
	}

	treeRes, err := e.mod.ExportedFunction("ts_parser_parse_string").Call(ctx, parserPtr, 0, uint64(srcPtr), uint64(len(source)))
	if err != nil {
		return nil, fmt.Errorf("ts_parser_parse_string: %w", err)
	}
	treePtr := treeRes[0]
	if treePtr == 0 {
		return nil, fmt.Errorf("parse returned null tree")
	}
	defer e.mod.ExportedFunction("ts_tree_delete").Call(ctx, treePtr)

	nodePtr, err := e.allocBuf(ctx, 32)
	if err != nil {
		return nil, err
	}
	defer e.free(ctx, nodePtr)
	e.mod.ExportedFunction("ts_tree_root_node").Call(ctx, uint64(nodePtr), treePtr)

	outBufSize := uint32(131072)
	outPtr, err := e.allocBuf(ctx, outBufSize)
	if err != nil {
		return nil, err
	}
	defer e.free(ctx, outPtr)

	extractFn := e.mod.ExportedFunction("extract_symbols")
	if extractFn == nil {
		return nil, fmt.Errorf("extract_symbols not exported")
	}

	runQuery := func(query string) ([]Symbol, error) {
		if query == "" {
			return nil, nil
		}
		qPtr, err := e.allocString(ctx, query)
		if err != nil {
			return nil, err
		}
		defer e.free(ctx, qPtr)

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

	result.Classes, err = runQuery(e.queries.classes)
	if err != nil {
		return nil, fmt.Errorf("class query: %w", err)
	}

	result.Functions, err = runQuery(e.queries.functions)
	if err != nil {
		return nil, fmt.Errorf("function query: %w", err)
	}

	result.Calls, err = runQuery(e.queries.calls)
	if err != nil {
		return nil, fmt.Errorf("call query: %w", err)
	}

	// Extract inheritance relationships
	inheritFn := e.mod.ExportedFunction("extract_inheritance")
	if inheritFn != nil {
		inhBufSize := uint32(32768)
		inhPtr, ierr := e.allocBuf(ctx, inhBufSize)
		if ierr == nil {
			defer e.free(ctx, inhPtr)
			zeros := make([]byte, inhBufSize)
			mem.Write(inhPtr, zeros)

			inhRes, ierr := inheritFn.Call(ctx,
				uint64(nodePtr),
				uint64(srcPtr),
				uint64(inhPtr), uint64(inhBufSize),
			)
			if ierr == nil {
				inhLen := uint32(inhRes[0])
				if inhLen > inhBufSize {
					inhLen = inhBufSize
				}
				if inhLen > 0 {
					inhBytes, ok := mem.Read(inhPtr, inhLen)
					if ok {
						result.Inheritance = parseInheritanceOutput(string(inhBytes))
					}
				}
			}
		}
	}

	return result, nil
}

// parseInheritanceOutput parses pipe-delimited output: class|parent|line
func parseInheritanceOutput(output string) []Inheritance {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var result []Inheritance
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 2 {
			continue
		}
		inh := Inheritance{
			ClassName:  parts[0],
			ParentName: parts[1],
		}
		if len(parts) >= 3 {
			fmt.Sscanf(parts[2], "%d", &inh.Line)
		}
		result = append(result, inh)
	}
	return result
}

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

func (e *engine) free(ctx context.Context, ptr uint32) {
	e.mod.ExportedFunction("ts_free").Call(ctx, uint64(ptr))
}
