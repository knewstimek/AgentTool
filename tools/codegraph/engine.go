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

// maxParsesPerEngine is the number of Parse calls before an engine is recycled.
// WASM linear memory only grows (never shrinks), so recycling periodically
// prevents unbounded memory growth when indexing large projects.
const maxParsesPerEngine = 50

// engine holds a wazero runtime and tree-sitter WASM module for one language.
// Parse is serialized with mu because WASM linear memory is shared.
type engine struct {
	runtime    wazero.Runtime
	mod        api.Module
	langPtr    uint64
	lang       string // language identifier
	queries    langQueries
	parserPtr  uint64 // cached parser (reused across Parse calls)
	outBufPtr  uint32 // cached output buffer
	outBufSz   uint32
	parseCount int // number of Parse calls; recycled when >= maxParsesPerEngine
}

// langQueries holds tree-sitter query patterns for a language.
type langQueries struct {
	classes   string
	functions string
	calls     string
	imports   string
}

// poolSize is the number of parallel engines per language.
// Each engine is ~7MB (WASM module), so 4 engines = ~28MB per language.
const poolSize = 4

// enginePool holds a pool of engines for one language.
type enginePool struct {
	ch chan *engine
}

var pools = struct {
	mu     sync.Mutex
	byLang map[string]*enginePool
}{byLang: make(map[string]*enginePool)}

// getEngine borrows an engine from the pool. Caller must call putEngine when done.
func getEngine(lang string) (*engine, error) {
	pools.mu.Lock()
	pool, ok := pools.byLang[lang]
	if !ok {
		pool = &enginePool{ch: make(chan *engine, poolSize)}
		pools.byLang[lang] = pool
	}
	pools.mu.Unlock()

	// Try to get an existing engine from pool (non-blocking)
	select {
	case e := <-pool.ch:
		return e, nil
	default:
	}

	// Pool empty, create a new one. More than poolSize engines may exist
	// temporarily under high concurrency. Excess are closed by putEngine.
	return newEngine(lang)
}

// putEngine returns an engine to the pool for reuse.
// Engines that have exceeded maxParsesPerEngine are discarded to free
// accumulated WASM linear memory.
func putEngine(e *engine) {
	// Recycle engine if it has parsed too many files
	if e.parseCount >= maxParsesPerEngine {
		e.runtime.Close(context.Background())
		return
	}

	pools.mu.Lock()
	pool, ok := pools.byLang[e.lang]
	pools.mu.Unlock()
	if !ok {
		return
	}

	// Return to pool if not full, otherwise discard
	select {
	case pool.ch <- e:
	default:
		// Pool full, close this engine
		e.runtime.Close(context.Background())
	}
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

	e := &engine{
		runtime: r,
		mod:     mod,
		langPtr: langRes[0],
		lang:    lang,
		queries: queries,
	}

	// Pre-allocate parser and output buffer for reuse
	ctx2 := context.Background()
	parserRes, err := mod.ExportedFunction("ts_parser_new").Call(ctx2)
	if err != nil {
		r.Close(ctx)
		return nil, fmt.Errorf("ts_parser_new failed (%s): %w", lang, err)
	}
	e.parserPtr = parserRes[0]

	setRes, err := mod.ExportedFunction("ts_parser_set_language").Call(ctx2, e.parserPtr, e.langPtr)
	if err != nil || setRes[0] == 0 {
		r.Close(ctx)
		return nil, fmt.Errorf("ts_parser_set_language failed (%s)", lang)
	}

	e.outBufSz = 131072 // 128KB
	outPtr, err := e.allocBuf(ctx2, e.outBufSz)
	if err != nil {
		r.Close(ctx)
		return nil, fmt.Errorf("alloc output buffer failed (%s): %w", lang, err)
	}
	e.outBufPtr = outPtr

	return e, nil
}

// langConfig returns WASM bytes and query patterns for a language.
func langConfig(lang string) ([]byte, langQueries, error) {
	switch lang {
	case "cpp":
		return cppWasm, langQueries{
			classes:   queryCPPClasses,
			functions: queryCPPFunctions,
			calls:     queryCPPCalls,
			imports:   queryCPPIncludes,
		}, nil
	case "python":
		return pythonWasm, langQueries{
			classes:   queryPythonClasses,
			functions: queryPythonFunctions,
			calls:     queryPythonCalls,
			imports:   queryPythonImports,
		}, nil
	case "go":
		return goWasm, langQueries{
			classes:   queryGoTypes,
			functions: queryGoFunctions,
			calls:     queryGoCalls,
			imports:   queryGoImports,
		}, nil
	case "csharp":
		return csharpWasm, langQueries{
			classes:   queryCSharpClasses,
			functions: queryCSharpFunctions,
			calls:     queryCSharpCalls,
			imports:   queryCSharpUsings,
		}, nil
	case "rust":
		return rustWasm, langQueries{
			classes:   queryRustTypes,
			functions: queryRustFunctions,
			calls:     queryRustCalls,
			imports:   queryRustUses,
		}, nil
	case "java":
		return javaWasm, langQueries{
			classes:   queryJavaClasses,
			functions: queryJavaFunctions,
			calls:     queryJavaCalls,
			imports:   queryJavaImports,
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
	Classes     []Symbol
	Functions   []Symbol
	Calls       []Symbol
	Imports     []Symbol
	Inheritance []Inheritance
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

// C/C++ include
const queryCPPIncludes = `
(preproc_include) @import
`

// Python imports
const queryPythonImports = `
(import_statement) @import
(import_from_statement) @import
`

// Go imports
const queryGoImports = `
(import_declaration) @import
`

// C# usings
const queryCSharpUsings = `
(using_directive) @import
`

// Rust use declarations
const queryRustUses = `
(use_declaration) @import
`

// Java imports
const queryJavaImports = `
(import_declaration) @import
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

// Parse parses source code and extracts all symbols in a single WASM call.
// Caller must ensure exclusive access (engine pool guarantees this).
func (e *engine) Parse(source string) (*ParseResult, error) {
	const maxSourceSize = 10 * 1024 * 1024
	if len(source) > maxSourceSize {
		return nil, fmt.Errorf("source too large (%d bytes, max %d)", len(source), maxSourceSize)
	}
	e.parseCount++

	ctx := context.Background()
	mem := e.mod.Memory()

	// Try fast path: parse_and_extract_all (single WASM call)
	fastFn := e.mod.ExportedFunction("parse_and_extract_all")
	if fastFn != nil {
		return e.parseFast(ctx, mem, fastFn, source)
	}

	// Fallback: individual calls (should not happen with current WASM builds)
	return e.parseSlow(ctx, mem, source)
}

// parseFast uses parse_and_extract_all for minimal WASM boundary crossings.
func (e *engine) parseFast(ctx context.Context, mem api.Memory, fastFn api.Function, source string) (*ParseResult, error) {
	srcPtr, err := e.allocString(ctx, source)
	if err != nil {
		return nil, err
	}
	defer e.free(ctx, srcPtr)

	// Allocate query strings
	cqPtr, err := e.allocString(ctx, e.queries.classes)
	if err != nil {
		return nil, err
	}
	defer e.free(ctx, cqPtr)

	fqPtr, err := e.allocString(ctx, e.queries.functions)
	if err != nil {
		return nil, err
	}
	defer e.free(ctx, fqPtr)

	callqPtr, err := e.allocString(ctx, e.queries.calls)
	if err != nil {
		return nil, err
	}
	defer e.free(ctx, callqPtr)

	impq := e.queries.imports
	if impq == "" {
		impq = " " // empty query placeholder
	}
	iqPtr, err := e.allocString(ctx, impq)
	if err != nil {
		return nil, err
	}
	defer e.free(ctx, iqPtr)

	// Clear output buffer
	outBufSize := e.outBufSz
	outPtr := e.outBufPtr
	zeros := make([]byte, outBufSize)
	mem.Write(outPtr, zeros)

	// Single WASM call: parse + 4 queries + inheritance
	res, err := fastFn.Call(ctx,
		e.langPtr,
		e.parserPtr,
		uint64(srcPtr), uint64(len(source)),
		uint64(cqPtr), uint64(len(e.queries.classes)),
		uint64(fqPtr), uint64(len(e.queries.functions)),
		uint64(callqPtr), uint64(len(e.queries.calls)),
		uint64(iqPtr), uint64(len(impq)),
		uint64(outPtr), uint64(outBufSize),
	)
	if err != nil {
		return nil, fmt.Errorf("parse_and_extract_all: %w", err)
	}

	resultLen := uint32(res[0])
	if resultLen == 0 {
		return &ParseResult{}, nil
	}
	if resultLen > outBufSize {
		resultLen = outBufSize
	}

	outBytes, ok := mem.Read(outPtr, resultLen)
	if !ok {
		return nil, fmt.Errorf("failed to read WASM output buffer")
	}

	output := string(outBytes)

	// Split by "---\n" separators: classes | functions | calls | imports | inheritance
	sections := strings.SplitN(output, "---\n", 5)

	result := &ParseResult{}
	if len(sections) > 0 {
		result.Classes = parseSymbolOutput(sections[0])
	}
	if len(sections) > 1 {
		result.Functions = parseSymbolOutput(sections[1])
	}
	if len(sections) > 2 {
		result.Calls = parseSymbolOutput(sections[2])
	}
	if len(sections) > 3 {
		result.Imports = parseSymbolOutput(sections[3])
	}
	if len(sections) > 4 {
		result.Inheritance = parseInheritanceOutput(sections[4])
	}

	return result, nil
}

// parseSlow is the fallback path using individual WASM calls.
func (e *engine) parseSlow(ctx context.Context, mem api.Memory, source string) (*ParseResult, error) {
	srcPtr, err := e.allocString(ctx, source)
	if err != nil {
		return nil, err
	}
	defer e.free(ctx, srcPtr)

	treeRes, err := e.mod.ExportedFunction("ts_parser_parse_string").Call(ctx, e.parserPtr, 0, uint64(srcPtr), uint64(len(source)))
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
	if _, err := e.mod.ExportedFunction("ts_tree_root_node").Call(ctx, uint64(nodePtr), treePtr); err != nil {
		return nil, fmt.Errorf("ts_tree_root_node: %w", err)
	}

	outBufSize := e.outBufSz
	outPtr := e.outBufPtr

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
			e.langPtr, uint64(nodePtr),
			uint64(qPtr), uint64(len(query)),
			uint64(srcPtr), uint64(outPtr), uint64(outBufSize),
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
	if err != nil { return nil, err }
	result.Functions, err = runQuery(e.queries.functions)
	if err != nil { return nil, err }
	result.Calls, err = runQuery(e.queries.calls)
	if err != nil { return nil, err }
	result.Imports, err = runQuery(e.queries.imports)
	if err != nil { return nil, err }
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
