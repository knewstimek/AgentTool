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
	Operation string `json:"operation" jsonschema:"Operation: disassemble, pe_info, elf_info, macho_info, strings, hexdump, pattern_search, entropy, bin_diff, resource_info, imphash, rich_header, overlay_detect, dwarf_info, xref, function_at, call_graph, follow_ptr, rtti_dump, struct_layout, vtable_scan,required"`
	FilePath  string `json:"file_path" jsonschema:"Absolute path to the binary file,required"`

	// disassemble / function_at / follow_ptr parameters
	Offset    int    `json:"offset,omitempty" jsonschema:"Byte offset to start from. Default: 0"`
	VA        string `json:"va,omitempty" jsonschema:"Virtual address for PE files (hex, e.g. '0x140001000'). Auto-converts to file offset. For disassemble, function_at, follow_ptr, rtti_dump, struct_layout. Preferred over offset+base_addr for PE analysis."`
	Count     int    `json:"count,omitempty" jsonschema:"Number of instructions (disassemble) or depth (follow_ptr). Default: 50/4, Max: 600/10."`
	StopAtRet bool   `json:"stop_at_ret,omitempty" jsonschema:"Stop disassembly at function return (RET/RETF). Confirms boundary via INT3/NOP padding or new prologue. For disassemble only."`
	Mode     int    `json:"mode,omitempty" jsonschema:"CPU mode: 32 or 64. Default: 64"`
	BaseAddr string `json:"base_addr,omitempty" jsonschema:"Base address for display (hex string, e.g. '0x140001000'). Default: 0x0. This maps to file offset 0, so displayed address = base_addr + offset + instruction_position. For PE files, prefer 'va' parameter instead -- it auto-calculates the correct base_addr."`
	Arch     string `json:"arch,omitempty" jsonschema:"CPU architecture: x86 (default) or arm. For disassemble"`

	// strings parameters
	MinLength  int    `json:"min_length,omitempty" jsonschema:"Minimum string length for strings operation. Default: 4"`
	MaxResults int    `json:"max_results,omitempty" jsonschema:"Maximum number of results for strings. Default: 500, Max: 2000"`
	Encoding   string `json:"encoding,omitempty" jsonschema:"String encoding to search for: ascii (default) or utf8"`

	// hexdump parameters
	Length int `json:"length,omitempty" jsonschema:"Number of bytes for hexdump. Default: 256, Max: 4096"`

	// pe_info / elf_info / macho_info parameters
	Section string `json:"section,omitempty" jsonschema:"Filter by section name (e.g. '.text', '.rdata'). Empty = show all"`
	RVA     string `json:"rva,omitempty" jsonschema:"RVA to convert to file offset (hex string, e.g. '0x36A20'). For pe_info only"`

	// pattern_search parameters
	Pattern string `json:"pattern,omitempty" jsonschema:"Hex byte pattern with ?? wildcards (e.g. '4D 5A ?? ?? 50 45'). For pattern_search"`

	// xref parameters
	TargetVA string `json:"target_va,omitempty" jsonschema:"Target virtual address to find references to (hex). For xref operation."`

	// bin_diff parameters
	FilePathB string `json:"file_path_b,omitempty" jsonschema:"Absolute path to the second file for bin_diff comparison"`

	// call_graph parameters are reused from VA + Count fields above
}

// Note: follow_ptr uses VA + Count, rtti_dump uses VA, struct_layout uses VA + Length

// AnalyzeOutput holds the tool result.
type AnalyzeOutput struct {
	Result string `json:"result"`
}

var validOperations = map[string]bool{
	"disassemble":    true,
	"pe_info":        true,
	"elf_info":       true,
	"macho_info":     true,
	"strings":        true,
	"hexdump":        true,
	"pattern_search": true,
	"entropy":        true,
	"bin_diff":       true,
	"resource_info":  true,
	"imphash":        true,
	"rich_header":    true,
	"overlay_detect": true,
	"dwarf_info":     true,
	"xref":           true,
	"function_at":    true,
	"call_graph":     true,
	"follow_ptr":     true,
	"rtti_dump":      true,
	"struct_layout":  true,
	"vtable_scan":   true,
}

// Handle dispatches to the appropriate operation.
func Handle(ctx context.Context, req *mcp.CallToolRequest, input AnalyzeInput) (*mcp.CallToolResult, AnalyzeOutput, error) {
	op := strings.ToLower(strings.TrimSpace(input.Operation))
	allOps := "disassemble, pe_info, elf_info, macho_info, strings, hexdump, pattern_search, entropy, bin_diff, resource_info, imphash, rich_header, overlay_detect, dwarf_info, xref, function_at, call_graph, follow_ptr, rtti_dump, struct_layout, vtable_scan"
	if op == "" {
		return errorResult("operation is required (" + allOps + ")")
	}
	if !validOperations[op] {
		return errorResult(fmt.Sprintf("unknown operation: %s (available: %s)", op, allOps))
	}

	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	// Normalize before validation to prevent path traversal (e.g. "/../")
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

	// No global file size check for analyze -- most operations (disassemble,
	// call_graph, xref, *_info) use lazy section-based reading and don't load
	// the entire file. Operations that do (strings, entropy, bin_diff) have
	// their own per-operation size checks. This allows analyzing multi-GB
	// binaries with debug symbols (common for game servers).

	var result string
	switch op {
	case "disassemble":
		result, err = opDisassemble(input)
	case "pe_info":
		result, err = opPEInfo(input)
	case "elf_info":
		result, err = opELFInfo(input)
	case "macho_info":
		result, err = opMachOInfo(input)
	case "strings":
		result, err = opStrings(input)
	case "hexdump":
		result, err = opHexdump(input)
	case "pattern_search":
		result, err = opPatternSearch(input)
	case "entropy":
		result, err = opEntropy(input)
	case "bin_diff":
		result, err = opBinDiff(input)
	case "resource_info":
		result, err = opResourceInfo(input)
	case "imphash":
		result, err = opImphash(input)
	case "rich_header":
		result, err = opRichHeader(input)
	case "overlay_detect":
		result, err = opOverlayDetect(input)
	case "dwarf_info":
		result, err = opDWARFInfo(input)
	case "xref":
		result, err = opXref(input)
	case "function_at":
		result, err = opFunctionAt(input)
	case "call_graph":
		result, err = opCallGraph(input)
	case "follow_ptr":
		result, err = opFollowPtr(input)
	case "rtti_dump":
		result, err = opRTTIDump(input)
	case "struct_layout":
		result, err = opStructLayout(input)
	case "vtable_scan":
		result, err = opVtableScan(input)
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
	common.SafeAddTool(server, &mcp.Tool{
		Name: "analyze",
		Description: `Static binary analysis tool for reverse engineering and debugging.
Operations: disassemble (x86/x64/ARM/ARM64 disassembly, stop_at_ret for function-scoped),
pe_info (PE header/sections/imports/exports),
elf_info (ELF header/sections/symbols), macho_info (Mach-O header/segments/symbols),
strings (extract printable strings from binary), hexdump (hex+ASCII view),
pattern_search (hex byte pattern with ?? wildcards, shows section names for PE),
entropy (Shannon entropy per section),
bin_diff (two-file byte comparison), resource_info (PE resources and version info),
imphash (PE import hash for malware classification), rich_header (PE build tool fingerprint),
overlay_detect (detect appended data after last section), dwarf_info (debug symbol info),
xref (find all code references to a target address in PE/ELF/Mach-O; supports x86/x64/ARM64/ARM32),
function_at (find function boundaries via PE .pdata or heuristic prologue/epilogue scan),
call_graph (static call graph from a root function; PE/ELF/Mach-O x86/x64, .pdata or heuristic detection),
follow_ptr (follow pointer chain in PE with symbol annotation, circular reference detection),
rtti_dump (parse MSVC RTTI from vtable: demangled class name + base classes, pSelf validation),
struct_layout (dump memory region as structured layout with symbol/section annotation),
vtable_scan (scan PE .rdata for all vtables with RTTI -- auto-discovers C++ classes).
Pure Go implementation -- no external tools needed. Supports x86, x64, ARM, ARM64.
For PE files: use 'va' parameter instead of 'offset' for auto VA display, symbol annotation, and function boundary detection.
PE strings/pattern_search automatically show VA alongside file offsets.
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
