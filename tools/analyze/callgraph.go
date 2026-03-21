package analyze

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

const (
	defaultCallGraphDepth    = 2
	maxCallGraphDepth        = 5
	defaultCallGraphMaxNodes = 200
	maxCallGraphMaxNodes     = 500
)

// cgEdge represents a caller->callee relationship in the call graph.
type cgEdge struct {
	callerVA uint64
	calleeVA uint64
}

// cgSection holds preloaded executable section data for CALL scanning.
type cgSection struct {
	rva  uint32
	data []byte
}

// opCallGraph builds a static call graph rooted at a given function VA.
// x64 PE: uses .pdata for precise function boundaries.
// x86 PE: heuristic mode -- detects functions from E8 CALL targets (no .pdata needed).
func opCallGraph(input AnalyzeInput) (string, error) {
	vaStr := input.VA
	if vaStr == "" && input.TargetVA != "" {
		vaStr = input.TargetVA
	}
	if vaStr == "" {
		return "", fmt.Errorf("va is required for call_graph (the root function address)")
	}

	rootVA, err := parseHexAddr(vaStr)
	if err != nil {
		return "", fmt.Errorf("invalid va: %s", vaStr)
	}

	// Open binary: try PE, then ELF, then Mach-O
	bin, err := cgOpenBinary(input.FilePath)
	if err != nil {
		return "", err
	}
	if bin.closer != nil {
		defer bin.closer()
	}

	imageBase := bin.imageBase
	if rootVA < imageBase {
		return "", fmt.Errorf("va 0x%x is below image base 0x%x", rootVA, imageBase)
	}
	if rootVA-imageBase > 0xFFFFFFFF {
		return "", fmt.Errorf("va 0x%x is too far from image base 0x%x (RVA exceeds 4GB)", rootVA, imageBase)
	}

	is64 := bin.is64

	depth := input.Count // reuse count parameter as max_depth
	if depth <= 0 {
		depth = defaultCallGraphDepth
	}
	if depth > maxCallGraphDepth {
		depth = maxCallGraphDepth
	}

	maxNodes := input.MaxResults
	if maxNodes <= 0 {
		maxNodes = defaultCallGraphMaxNodes
	}
	if maxNodes > maxCallGraphMaxNodes {
		maxNodes = maxCallGraphMaxNodes
	}

	symbols := bin.symbols
	execSections := bin.execSections
	funcTable := bin.funcTable

	// Resolve root function
	rootRVA := uint32(rootVA - imageBase)
	rootFunc := findFunc(funcTable, rootRVA)
	if rootFunc == nil {
		if isInExecSection(execSections, rootRVA) {
			// Heuristic: root may not be a CALL/BL target (e.g. entry point,
			// indirect call target). Insert it into the table so BFS can proceed.
			funcTable = insertFunc(funcTable, rootRVA, execSections)
			rootFunc = findFunc(funcTable, rootRVA)
		}
		if rootFunc == nil {
			return "", fmt.Errorf("no function found at 0x%x. "+
				"Try function_at with va=\"0x%x\" to find the nearest function", rootVA, rootVA)
		}
	}

	// BFS to build call graph
	visited := make(map[uint64]int)          // VA -> depth at which visited
	imports := make(map[uint64][]string)     // caller VA -> imported function names (FF 15)
	var edges []cgEdge
	type bfsItem struct {
		va    uint64
		depth int
	}
	queue := []bfsItem{{va: imageBase + uint64(rootFunc.begin), depth: 0}}
	visited[imageBase+uint64(rootFunc.begin)] = 0

	for len(queue) > 0 && len(visited) < maxNodes {
		cur := queue[0]
		queue = queue[1:]

		if cur.depth >= depth {
			continue
		}

		curRVA := uint32(cur.va - imageBase)
		curFn := findFunc(funcTable, curRVA)
		if curFn == nil {
			continue
		}

		// Scan this function's code for CALL/BL targets (arch-specific)
		var callees []cgCallTarget
		switch bin.arch {
		case "arm64":
			callees = scanCallTargetsARM64(execSections, curFn.begin, curFn.end, imageBase)
		case "arm32":
			callees = scanCallTargetsARM32(execSections, curFn.begin, curFn.end, imageBase)
		default: // x86, x64
			callees = scanCallTargets(execSections, curFn.begin, curFn.end, imageBase, is64)
		}

		for _, ct := range callees {
			if ct.indirect {
				// FF 15 [rip+disp32]: target is an IAT slot RVA (in .rdata, not .text).
				// Record as import call -- no BFS expansion (external function).
				iatVA := imageBase + uint64(ct.rva)
				if name, ok := symbols[iatVA]; ok {
					imports[cur.va] = append(imports[cur.va], name)
				}
				continue
			}

			// E8 rel32: filter false positives by checking executable section range.
			if !isInExecSection(execSections, ct.rva) {
				continue
			}

			calleeVA := imageBase + uint64(ct.rva)
			edges = append(edges, cgEdge{callerVA: cur.va, calleeVA: calleeVA})

			if _, seen := visited[calleeVA]; !seen && len(visited) < maxNodes {
				visited[calleeVA] = cur.depth + 1
				// Only BFS-expand if callee is a known .pdata function start.
				// Leaf functions (no .pdata entry) are shown as edges but not
				// expanded, since we can't determine their code boundaries.
				calleeFn := findFunc(funcTable, ct.rva)
				if calleeFn != nil && calleeFn.begin == ct.rva {
					queue = append(queue, bfsItem{va: calleeVA, depth: cur.depth + 1})
				}
			}
		}
	}

	// Also find callers of root (reverse direction, 1 level only)
	var rootCallers []uint32
	switch bin.arch {
	case "arm64":
		rootCallers = findCallersARM64(execSections, rootFunc.begin, imageBase, funcTable)
	case "arm32":
		rootCallers = findCallersARM32(execSections, rootFunc.begin, imageBase, funcTable)
	default:
		rootCallers = findCallers(execSections, rootFunc.begin, imageBase, funcTable, is64)
	}

	// Format output
	var sb strings.Builder
	rootName := funcName(imageBase+uint64(rootFunc.begin), symbols)
	mode := ""
	if bin.arch != "x64" {
		// x86/ARM use heuristic function detection (no .pdata)
		mode = ", heuristic"
	}
	sb.WriteString(fmt.Sprintf("Call graph for %s (depth=%d, %d nodes%s):\n\n", rootName, depth, len(visited), mode))

	// Print callers
	if len(rootCallers) > 0 {
		sb.WriteString(fmt.Sprintf("Callers of %s:\n", rootName))
		for _, callerRVA := range rootCallers {
			callerVA := imageBase + uint64(callerRVA)
			sb.WriteString(fmt.Sprintf("  <- %s\n", funcName(callerVA, symbols)))
		}
		sb.WriteString("\n")
	}

	// Print callees as tree
	sb.WriteString("Callees:\n")
	printCallTree(&sb, imageBase+uint64(rootFunc.begin), edges, imports, symbols, 0, depth, make(map[uint64]bool))

	if len(visited) >= maxNodes {
		sb.WriteString(fmt.Sprintf("\n(truncated at max_nodes=%d)\n", maxNodes))
	}

	return sb.String(), nil
}

// funcRange represents a function's RVA range.
type funcRange struct {
	begin uint32
	end   uint32
}

// buildFuncTable extracts all function ranges from .pdata.
// Returns sorted slice for binary search.
func buildFuncTable(f *pe.File, imageBase uint64) []funcRange {
	oh64, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || len(oh64.DataDirectory) <= 3 {
		return nil
	}
	excDir := oh64.DataDirectory[3]
	if excDir.VirtualAddress == 0 || excDir.Size < 12 {
		return nil
	}

	// Read .pdata via section
	var pdataData []byte
	for _, s := range f.Sections {
		if excDir.VirtualAddress >= s.VirtualAddress &&
			excDir.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			secData, err := s.Data()
			if err != nil {
				return nil
			}
			off := excDir.VirtualAddress - s.VirtualAddress
			if uint64(off) >= uint64(len(secData)) {
				return nil
			}
			end64 := uint64(off) + uint64(excDir.Size)
			if end64 > uint64(len(secData)) {
				end64 = uint64(len(secData))
			}
			pdataData = secData[off:end64]
			break
		}
	}
	if len(pdataData) < 12 {
		return nil
	}

	count := len(pdataData) / 12
	if count > 500000 {
		count = 500000
	}

	table := make([]funcRange, 0, count)
	for i := 0; i < count; i++ {
		off := i * 12
		begin := binary.LittleEndian.Uint32(pdataData[off:])
		end := binary.LittleEndian.Uint32(pdataData[off+4:])
		if begin < end {
			table = append(table, funcRange{begin: begin, end: end})
		}
	}

	sort.Slice(table, func(i, j int) bool { return table[i].begin < table[j].begin })
	return table
}

// isInExecSection checks if an RVA falls within any executable section.
// Used to filter false positive CALL targets that land outside code.
func isInExecSection(sections []cgSection, rva uint32) bool {
	for _, sec := range sections {
		if uint64(rva) >= uint64(sec.rva) && uint64(rva) < uint64(sec.rva)+uint64(len(sec.data)) {
			return true
		}
	}
	return false
}

// findFunc finds the function containing rva via binary search on the func table.
func findFunc(table []funcRange, rva uint32) *funcRange {
	idx := sort.Search(len(table), func(i int) bool { return table[i].begin > rva })
	if idx == 0 {
		return nil
	}
	fn := &table[idx-1]
	if rva >= fn.begin && rva < fn.end {
		return fn
	}
	return nil
}

// cgCallTarget represents a call target found by scanCallTargets.
type cgCallTarget struct {
	rva      uint32
	indirect bool // true = FF 15 [rip+disp32] (IAT slot), false = E8 rel32 (direct)
}

// scanCallTargets extracts CALL target RVAs from a function's code.
// Scans E8 rel32 (direct) and FF 15 [rip+disp32] (indirect via IAT).
// Returns deduplicated list sorted by RVA.
func scanCallTargets(sections []cgSection, funcBegin, funcEnd uint32, imageBase uint64, is64 bool) []cgCallTarget {
	seen := make(map[uint32]bool)
	var targets []cgCallTarget
	mode := 32
	if is64 {
		mode = 64
	}

	for _, sec := range sections {
		secEnd64 := uint64(sec.rva) + uint64(len(sec.data))

		// Check overlap with function range (use uint64 to avoid uint32 wrap-around)
		scanStart := funcBegin
		if scanStart < sec.rva {
			scanStart = sec.rva
		}
		scanEnd := funcEnd
		if uint64(scanEnd) > secEnd64 {
			scanEnd = uint32(secEnd64)
		}
		if scanStart >= scanEnd {
			continue
		}

		data := sec.data[scanStart-sec.rva : scanEnd-sec.rva]

		// Instruction-level scan to avoid false positives from mid-instruction bytes
		for i := 0; i < len(data); {
			instrRVA := scanStart + uint32(i)
			inst, err := x86asm.Decode(data[i:], mode)
			if err != nil || inst.Len <= 0 {
				i++
				continue
			}
			instBytes := data[i : i+inst.Len]

			// E8 rel32 -- CALL relative (direct call)
			if instBytes[0] == 0xE8 && inst.Len == 5 {
				rel := int32(binary.LittleEndian.Uint32(instBytes[1:]))
				target := uint32(int64(instrRVA) + 5 + int64(rel))
				if !seen[target] {
					seen[target] = true
					targets = append(targets, cgCallTarget{rva: target, indirect: false})
				}
			}

			// FF 15 -- indirect call via IAT
			// x64: CALL [rip+disp32], x86: CALL [abs32]
			if instBytes[0] == 0xFF && inst.Len >= 6 && instBytes[1] == 0x15 {
				var target uint32
				var valid bool
				if is64 {
					disp := int32(binary.LittleEndian.Uint32(instBytes[2:6]))
					target = uint32(int64(instrRVA) + int64(inst.Len) + int64(disp))
					valid = true
				} else {
					// x86 FF 15: absolute address, convert to RVA
					addr := binary.LittleEndian.Uint32(instBytes[2:6])
					base32 := uint32(imageBase)
					if addr >= base32 {
						target = addr - base32
						valid = true
					}
				}
				if valid && !seen[target] {
					seen[target] = true
					targets = append(targets, cgCallTarget{rva: target, indirect: true})
				}
			}

			i += inst.Len
		}
	}

	sort.Slice(targets, func(i, j int) bool { return targets[i].rva < targets[j].rva })
	return targets
}

// findCallers scans all executable code for CALL instructions targeting funcBeginRVA.
// Returns RVAs of functions that contain such calls (deduplicated).
// Uses instruction-level decoding to avoid false positives from mid-instruction bytes.
func findCallers(sections []cgSection, targetRVA uint32, imageBase uint64, funcTable []funcRange, is64 bool) []uint32 {
	seen := make(map[uint32]bool)
	var callers []uint32
	mode := 32
	if is64 {
		mode = 64
	}

	for _, sec := range sections {
		data := sec.data
		for i := 0; i < len(data); {
			inst, err := x86asm.Decode(data[i:], mode)
			if err != nil || inst.Len <= 0 {
				i++
				continue
			}
			if data[i] == 0xE8 && inst.Len == 5 {
				instrRVA := sec.rva + uint32(i)
				rel := int32(binary.LittleEndian.Uint32(data[i+1:]))
				target := uint32(int64(instrRVA) + 5 + int64(rel))
				if target == targetRVA {
					fn := findFunc(funcTable, instrRVA)
					if fn != nil && !seen[fn.begin] {
						seen[fn.begin] = true
						callers = append(callers, fn.begin)
					}
				}
			}
			i += inst.Len
		}
	}

	sort.Slice(callers, func(i, j int) bool { return callers[i] < callers[j] })
	return callers
}

// funcName formats a VA with symbol name if available.
func funcName(va uint64, symbols map[uint64]string) string {
	if name, ok := symbols[va]; ok {
		return fmt.Sprintf("0x%x %s", va, name)
	}
	return fmt.Sprintf("0x%x", va)
}

// printCallTree recursively prints the call tree with indentation.
// imports maps caller VA -> list of imported API names (from FF 15 indirect calls).
func printCallTree(sb *strings.Builder, va uint64, edges []cgEdge, imports map[uint64][]string, symbols map[uint64]string, curDepth, maxDepth int, printed map[uint64]bool) {
	indent := strings.Repeat("  ", curDepth)
	name := funcName(va, symbols)

	if printed[va] {
		sb.WriteString(fmt.Sprintf("%s-> %s (already shown)\n", indent, name))
		return
	}

	if curDepth == 0 {
		sb.WriteString(fmt.Sprintf("%s%s\n", indent, name))
	}
	printed[va] = true

	if curDepth >= maxDepth {
		return
	}

	// Find children (direct calls)
	var children []uint64
	childSeen := make(map[uint64]bool)
	for _, e := range edges {
		if e.callerVA == va && !childSeen[e.calleeVA] {
			childSeen[e.calleeVA] = true
			children = append(children, e.calleeVA)
		}
	}

	for _, child := range children {
		childName := funcName(child, symbols)
		if printed[child] {
			sb.WriteString(fmt.Sprintf("%s  -> %s (already shown)\n", indent, childName))
		} else {
			sb.WriteString(fmt.Sprintf("%s  -> %s\n", indent, childName))
			printCallTree(sb, child, edges, imports, symbols, curDepth+1, maxDepth, printed)
		}
	}

	// Show imported API calls (indirect via IAT)
	if apiNames, ok := imports[va]; ok && len(apiNames) > 0 {
		for _, apiName := range apiNames {
			sb.WriteString(fmt.Sprintf("%s  -> %s [IAT]\n", indent, apiName))
		}
	}
}

// buildFuncTableFromCalls detects x86 function boundaries heuristically
// by collecting all E8 CALL targets that land in executable sections.
// Each target is assumed to be a function entry; the function extends
// until the next detected entry or section end.
func buildFuncTableFromCalls(sections []cgSection, imageBase uint64) []funcRange {
	// Step 1: collect unique E8 CALL targets via instruction-level scan
	starts := make(map[uint32]bool)
	for _, sec := range sections {
		data := sec.data
		for i := 0; i < len(data); {
			inst, err := x86asm.Decode(data[i:], 32)
			if err != nil || inst.Len <= 0 {
				i++
				continue
			}
			if data[i] == 0xE8 && inst.Len == 5 {
				instrRVA := sec.rva + uint32(i)
				rel := int32(binary.LittleEndian.Uint32(data[i+1:]))
				target := uint32(int64(instrRVA) + 5 + int64(rel))
				if isInExecSection(sections, target) {
					starts[target] = true
				}
			}
			i += inst.Len
		}
	}

	if len(starts) == 0 {
		return nil
	}

	// Step 2: sort unique function starts
	sorted := make([]uint32, 0, len(starts))
	for s := range starts {
		sorted = append(sorted, s)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	// Step 3: build funcRange -- end = min(next func start, section end)
	table := make([]funcRange, 0, len(sorted))
	for i, begin := range sorted {
		// Find section boundary for this function
		var secEnd uint32
		for _, sec := range sections {
			se64 := uint64(sec.rva) + uint64(len(sec.data))
			if se64 > 0xFFFFFFFF {
				se64 = 0xFFFFFFFF
			}
			if uint64(begin) >= uint64(sec.rva) && uint64(begin) < se64 {
				secEnd = uint32(se64)
				break
			}
		}
		if secEnd <= begin {
			continue
		}

		var end uint32
		if i+1 < len(sorted) && sorted[i+1] < secEnd {
			// Next function is within same section
			end = sorted[i+1]
		} else {
			// Last function in section or next function is in different section
			end = secEnd
		}
		if end > begin {
			table = append(table, funcRange{begin: begin, end: end})
		}
	}

	return table
}

// insertFunc adds a function entry at rva into a sorted funcTable,
// splitting an existing range if necessary. Used when the root VA
// is not a known CALL target (e.g. entry point, indirect call target).
func insertFunc(table []funcRange, rva uint32, sections []cgSection) []funcRange {
	// Already in table as a function start?
	if fn := findFunc(table, rva); fn != nil && fn.begin == rva {
		return table
	}

	// Find end: next function start after rva, or section end
	var end uint32
	idx := sort.Search(len(table), func(i int) bool { return table[i].begin > rva })
	if idx < len(table) {
		end = table[idx].begin
	} else {
		for _, sec := range sections {
			secEnd64 := uint64(sec.rva) + uint64(len(sec.data))
			if uint64(rva) >= uint64(sec.rva) && uint64(rva) < secEnd64 {
				if secEnd64 > 0xFFFFFFFF {
					secEnd64 = 0xFFFFFFFF
				}
				end = uint32(secEnd64)
				break
			}
		}
	}
	if end <= rva {
		return table
	}

	// Insert and re-sort
	table = append(table, funcRange{begin: rva, end: end})
	sort.Slice(table, func(i, j int) bool { return table[i].begin < table[j].begin })

	// Fix previous entry's end if it was split (re-find after sort)
	newIdx := sort.Search(len(table), func(i int) bool { return table[i].begin >= rva })
	if newIdx > 0 && table[newIdx-1].end > rva {
		table[newIdx-1].end = rva
	}

	return table
}

// cgBinary holds parsed binary info for call graph analysis.
type cgBinary struct {
	imageBase    uint64
	is64         bool
	arch         string // "x86" or "x64"
	format       string // "PE", "ELF", "Mach-O"
	symbols      map[uint64]string
	execSections []cgSection
	funcTable    []funcRange
	closer       func()
}

// cgOpenBinary tries PE, ELF, Mach-O in order and returns a cgBinary.
func cgOpenBinary(path string) (*cgBinary, error) {
	// Try PE first
	if bin, err := cgOpenPE(path); err == nil {
		return bin, nil
	}
	// Try ELF
	if bin, err := cgOpenELF(path); err == nil {
		return bin, nil
	}
	// Try Mach-O
	if bin, err := cgOpenMachO(path); err == nil {
		return bin, nil
	}
	return nil, fmt.Errorf("cannot open %s as PE/ELF/Mach-O", path)
}

// cgOpenPE opens a PE binary and extracts call graph info.
func cgOpenPE(path string) (*cgBinary, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}

	imageBase := peImageBase(f)
	if imageBase == 0 {
		f.Close()
		return nil, fmt.Errorf("PE: no optional header")
	}

	var is64 bool
	switch f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		is64 = true
	}

	arch := "x86"
	if is64 {
		arch = "x64"
	}

	// Load executable sections
	var execSections []cgSection
	for _, s := range f.Sections {
		if s.Characteristics&0x20000000 != 0 { // IMAGE_SCN_MEM_EXECUTE
			data, err := s.Data()
			if err != nil {
				continue
			}
			execSections = append(execSections, cgSection{rva: s.VirtualAddress, data: data})
		}
	}
	if len(execSections) == 0 {
		f.Close()
		return nil, fmt.Errorf("PE: no executable sections")
	}

	// Build function table
	var funcTable []funcRange
	if is64 {
		funcTable = buildFuncTable(f, imageBase)
		if len(funcTable) == 0 {
			// x64 PE without .pdata: fall back to heuristic
			funcTable = buildFuncTableFromCalls(execSections, imageBase)
		}
	} else {
		// x86 PE: no .pdata, use heuristic
		funcTable = buildFuncTableFromCalls(execSections, imageBase)
	}

	symbols := peSymbolMap(f, imageBase)

	return &cgBinary{
		imageBase:    imageBase,
		is64:         is64,
		arch:         arch,
		format:       "PE",
		symbols:      symbols,
		execSections: execSections,
		funcTable:    funcTable,
		closer:       func() { f.Close() },
	}, nil
}

// cgOpenELF opens an ELF binary and extracts call graph info.
func cgOpenELF(path string) (*cgBinary, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}

	var is64 bool
	var arch string
	switch f.Machine {
	case elf.EM_386:
		arch = "x86"
	case elf.EM_X86_64:
		arch = "x64"
		is64 = true
	case elf.EM_AARCH64:
		arch = "arm64"
		is64 = true
	case elf.EM_ARM:
		arch = "arm32"
	default:
		f.Close()
		return nil, fmt.Errorf("ELF: unsupported machine %v", f.Machine)
	}

	// ELF imageBase = lowest PT_LOAD virtual address. Unlike PE (which stores
	// imageBase in the optional header), ELF uses the first loadable segment's
	// vaddr as the base for RVA calculations.
	var imageBase uint64 = ^uint64(0)
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Vaddr < imageBase {
			imageBase = p.Vaddr
		}
	}
	if imageBase == ^uint64(0) {
		imageBase = 0
	}

	// Executable sections (SHF_EXECINSTR)
	var execSections []cgSection
	for _, s := range f.Sections {
		if s.Flags&elf.SHF_EXECINSTR != 0 && s.Size > 0 {
			data, err := s.Data()
			if err != nil || len(data) == 0 {
				continue
			}
			// Guard: s.Addr < imageBase would cause uint64 underflow in subtraction
			if s.Addr < imageBase {
				continue
			}
			rva64 := s.Addr - imageBase
			// RVA must fit in uint32 for cgSection.rva and all scan functions
			if rva64 > 0xFFFFFFFF {
				continue
			}
			execSections = append(execSections, cgSection{rva: uint32(rva64), data: data})
		}
	}
	if len(execSections) == 0 {
		f.Close()
		return nil, fmt.Errorf("ELF: no executable sections")
	}

	// Heuristic function table from CALL/BL targets
	var funcTable []funcRange
	switch arch {
	case "arm64":
		funcTable = buildFuncTableFromCallsARM64(execSections, imageBase)
	case "arm32":
		funcTable = buildFuncTableFromCallsARM32(execSections, imageBase)
	default:
		funcTable = buildFuncTableFromCalls(execSections, imageBase)
	}

	// Merge ELF symbol table entries as function starts. Heuristic CALL-target
	// detection alone misses functions only reached via indirect calls, jump
	// tables, or tail calls. Symbol tables provide authoritative entry points.
	symbols := elfSymbolMap(f, imageBase)
	if len(symbols) > 0 {
		for va := range symbols {
			if va < imageBase {
				continue
			}
			rva64 := va - imageBase
			if rva64 > 0xFFFFFFFF {
				continue // symbol beyond uint32 RVA range
			}
			rva := uint32(rva64)
			if isInExecSection(execSections, rva) {
				if fn := findFunc(funcTable, rva); fn == nil || fn.begin != rva {
					funcTable = insertFunc(funcTable, rva, execSections)
				}
			}
		}
	}

	return &cgBinary{
		imageBase:    imageBase,
		is64:         is64,
		arch:         arch,
		format:       "ELF",
		symbols:      symbols,
		execSections: execSections,
		funcTable:    funcTable,
		closer:       func() { f.Close() },
	}, nil
}

// cgOpenMachO opens a Mach-O binary and extracts call graph info.
func cgOpenMachO(path string) (*cgBinary, error) {
	f, err := macho.Open(path)
	if err != nil {
		return nil, err
	}

	var is64 bool
	var arch string
	switch f.Cpu {
	case macho.Cpu386:
		arch = "x86"
	case macho.CpuAmd64:
		arch = "x64"
		is64 = true
	case macho.CpuArm64:
		arch = "arm64"
		is64 = true
	case macho.CpuArm:
		arch = "arm32"
	default:
		f.Close()
		return nil, fmt.Errorf("Mach-O: unsupported CPU %v", f.Cpu)
	}

	// Mach-O imageBase = __TEXT segment virtual address. This is the conventional
	// base for Mach-O binaries; all code sections live within __TEXT.
	var imageBase uint64
	for _, seg := range f.Loads {
		if s, ok := seg.(*macho.Segment); ok && s.Name == "__TEXT" {
			imageBase = s.Addr
			break
		}
	}

	// Executable sections (in __TEXT segment)
	var execSections []cgSection
	for _, s := range f.Sections {
		if s.Seg == "__TEXT" && s.Size > 0 {
			data, err := s.Data()
			if err != nil || len(data) == 0 {
				continue
			}
			// Guard: s.Addr < imageBase would cause uint64 underflow in subtraction
			if s.Addr < imageBase {
				continue
			}
			rva64 := s.Addr - imageBase
			// RVA must fit in uint32 for cgSection.rva and all scan functions
			if rva64 > 0xFFFFFFFF {
				continue
			}
			execSections = append(execSections, cgSection{rva: uint32(rva64), data: data})
		}
	}
	if len(execSections) == 0 {
		f.Close()
		return nil, fmt.Errorf("Mach-O: no executable sections")
	}

	// Heuristic function table from CALL/BL targets
	var funcTable []funcRange
	switch arch {
	case "arm64":
		funcTable = buildFuncTableFromCallsARM64(execSections, imageBase)
	case "arm32":
		funcTable = buildFuncTableFromCallsARM32(execSections, imageBase)
	default:
		funcTable = buildFuncTableFromCalls(execSections, imageBase)
	}

	// Merge Mach-O symbol table entries as function starts (same rationale as ELF)
	symbols := machoSymbolMap(f, imageBase)
	if len(symbols) > 0 {
		for va := range symbols {
			if va < imageBase {
				continue
			}
			rva64 := va - imageBase
			if rva64 > 0xFFFFFFFF {
				continue // symbol beyond uint32 RVA range
			}
			rva := uint32(rva64)
			if isInExecSection(execSections, rva) {
				if fn := findFunc(funcTable, rva); fn == nil || fn.begin != rva {
					funcTable = insertFunc(funcTable, rva, execSections)
				}
			}
		}
	}

	return &cgBinary{
		imageBase:    imageBase,
		is64:         is64,
		arch:         arch,
		format:       "Mach-O",
		symbols:      symbols,
		execSections: execSections,
		funcTable:    funcTable,
		closer:       func() { f.Close() },
	}, nil
}

// elfSymbolMap builds a VA->name map from ELF .symtab and .dynsym.
func elfSymbolMap(f *elf.File, imageBase uint64) map[uint64]string {
	m := make(map[uint64]string)
	// .symtab
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			if s.Name != "" && s.Value != 0 {
				m[s.Value] = s.Name
			}
		}
	}
	// .dynsym
	if syms, err := f.DynamicSymbols(); err == nil {
		for _, s := range syms {
			if s.Name != "" && s.Value != 0 {
				if _, exists := m[s.Value]; !exists {
					m[s.Value] = s.Name
				}
			}
		}
	}
	return m
}

// machoSymbolMap builds a VA->name map from Mach-O symbol table.
func machoSymbolMap(f *macho.File, imageBase uint64) map[uint64]string {
	m := make(map[uint64]string)
	if f.Symtab == nil {
		return m
	}
	for _, s := range f.Symtab.Syms {
		if s.Name != "" && s.Value != 0 {
			m[s.Value] = s.Name
		}
	}
	return m
}

// --- ARM64 call graph support ---

// buildFuncTableFromCallsARM64 detects function boundaries by collecting
// BL (Branch with Link) targets that land in executable sections.
func buildFuncTableFromCallsARM64(sections []cgSection, imageBase uint64) []funcRange {
	starts := make(map[uint32]bool)
	for _, sec := range sections {
		data := sec.data
		for i := 0; i+4 <= len(data); i += 4 {
			instr := binary.LittleEndian.Uint32(data[i:])
			// BL imm26: 1001 01ii iiii iiii iiii iiii iiii iiii
			if instr>>26 != 0x25 {
				continue
			}
			instrRVA := sec.rva + uint32(i)
			instrVA := imageBase + uint64(instrRVA)
			imm26 := int32(instr&0x03FFFFFF) << 6 >> 6
			targetVA := instrVA + uint64(int64(imm26)*4)
			if targetVA < imageBase {
				continue
			}
			tRVA64 := targetVA - imageBase
			if tRVA64 > 0xFFFFFFFF {
				continue
			}
			target := uint32(tRVA64)
			if isInExecSection(sections, target) {
				starts[target] = true
			}
		}
	}
	return buildFuncRangesFromStarts(starts, sections)
}

// buildFuncTableFromCallsARM32 detects function boundaries by collecting
// BL (Branch with Link) targets. Uses PC+8 pipeline offset for ARM32.
func buildFuncTableFromCallsARM32(sections []cgSection, imageBase uint64) []funcRange {
	starts := make(map[uint32]bool)
	for _, sec := range sections {
		data := sec.data
		for i := 0; i+4 <= len(data); i += 4 {
			instr := binary.LittleEndian.Uint32(data[i:])
			// BL imm24: cccc 1011 iiii iiii iiii iiii iiii iiii
			// Skip cond==0xF: unconditional extension space (BLX uses different
			// target calc with H-bit halfword offset, not handled here)
			if instr>>28 == 0x0F {
				continue
			}
			if (instr>>24)&0x0F != 0x0B {
				continue
			}
			instrRVA := sec.rva + uint32(i)
			instrVA := imageBase + uint64(instrRVA)
			imm24 := int32(instr&0x00FFFFFF) << 8 >> 8
			// ARM32 PC = instrAddr + 8 (pipeline offset)
			targetVA := instrVA + 8 + uint64(int64(imm24)*4)
			if targetVA < imageBase {
				continue
			}
			tRVA64 := targetVA - imageBase
			if tRVA64 > 0xFFFFFFFF {
				continue
			}
			target := uint32(tRVA64)
			if isInExecSection(sections, target) {
				starts[target] = true
			}
		}
	}
	return buildFuncRangesFromStarts(starts, sections)
}

// buildFuncRangesFromStarts converts a set of function start RVAs into
// sorted funcRange slice. Shared by ARM64 and ARM32 table builders.
func buildFuncRangesFromStarts(starts map[uint32]bool, sections []cgSection) []funcRange {
	if len(starts) == 0 {
		return nil
	}
	sorted := make([]uint32, 0, len(starts))
	for s := range starts {
		sorted = append(sorted, s)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	table := make([]funcRange, 0, len(sorted))
	for i, begin := range sorted {
		var secEnd uint32
		for _, sec := range sections {
			se64 := uint64(sec.rva) + uint64(len(sec.data))
			if se64 > 0xFFFFFFFF {
				se64 = 0xFFFFFFFF
			}
			if uint64(begin) >= uint64(sec.rva) && uint64(begin) < se64 {
				secEnd = uint32(se64)
				break
			}
		}
		if secEnd <= begin {
			continue
		}
		var end uint32
		if i+1 < len(sorted) && sorted[i+1] < secEnd {
			end = sorted[i+1]
		} else {
			end = secEnd
		}
		if end > begin {
			table = append(table, funcRange{begin: begin, end: end})
		}
	}
	return table
}

// scanCallTargetsARM64 extracts BL target RVAs from an ARM64 function's code.
func scanCallTargetsARM64(sections []cgSection, funcBegin, funcEnd uint32, imageBase uint64) []cgCallTarget {
	seen := make(map[uint32]bool)
	var targets []cgCallTarget

	for _, sec := range sections {
		secEnd64 := uint64(sec.rva) + uint64(len(sec.data))
		if secEnd64 > 0xFFFFFFFF {
			secEnd64 = 0xFFFFFFFF
		}
		scanStart := funcBegin
		if scanStart < sec.rva {
			scanStart = sec.rva
		}
		scanEnd := funcEnd
		if uint64(scanEnd) > secEnd64 {
			scanEnd = uint32(secEnd64)
		}
		if scanStart >= scanEnd {
			continue
		}

		data := sec.data[scanStart-sec.rva : scanEnd-sec.rva]
		for i := 0; i+4 <= len(data); i += 4 {
			instr := binary.LittleEndian.Uint32(data[i:])
			// BL imm26
			if instr>>26 != 0x25 {
				continue
			}
			instrRVA := scanStart + uint32(i)
			instrVA := imageBase + uint64(instrRVA)
			imm26 := int32(instr&0x03FFFFFF) << 6 >> 6
			targetVA := instrVA + uint64(int64(imm26)*4)
			if targetVA < imageBase {
				continue
			}
			tRVA64 := targetVA - imageBase
			if tRVA64 > 0xFFFFFFFF {
				continue
			}
			target := uint32(tRVA64)
			if !seen[target] {
				seen[target] = true
				targets = append(targets, cgCallTarget{rva: target, indirect: false})
			}
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].rva < targets[j].rva })
	return targets
}

// scanCallTargetsARM32 extracts BL target RVAs from an ARM32 function's code.
func scanCallTargetsARM32(sections []cgSection, funcBegin, funcEnd uint32, imageBase uint64) []cgCallTarget {
	seen := make(map[uint32]bool)
	var targets []cgCallTarget

	for _, sec := range sections {
		secEnd64 := uint64(sec.rva) + uint64(len(sec.data))
		if secEnd64 > 0xFFFFFFFF {
			secEnd64 = 0xFFFFFFFF
		}
		scanStart := funcBegin
		if scanStart < sec.rva {
			scanStart = sec.rva
		}
		scanEnd := funcEnd
		if uint64(scanEnd) > secEnd64 {
			scanEnd = uint32(secEnd64)
		}
		if scanStart >= scanEnd {
			continue
		}

		data := sec.data[scanStart-sec.rva : scanEnd-sec.rva]
		for i := 0; i+4 <= len(data); i += 4 {
			instr := binary.LittleEndian.Uint32(data[i:])
			// Skip cond==0xF: unconditional extension space (BLX uses different
			// target calc with H-bit halfword offset, not handled here)
			if instr>>28 == 0x0F {
				continue
			}
			// BL imm24: cccc 1011 ...
			if (instr>>24)&0x0F != 0x0B {
				continue
			}
			instrRVA := scanStart + uint32(i)
			instrVA := imageBase + uint64(instrRVA)
			imm24 := int32(instr&0x00FFFFFF) << 8 >> 8
			targetVA := instrVA + 8 + uint64(int64(imm24)*4)
			if targetVA < imageBase {
				continue
			}
			tRVA64 := targetVA - imageBase
			if tRVA64 > 0xFFFFFFFF {
				continue
			}
			target := uint32(tRVA64)
			if !seen[target] {
				seen[target] = true
				targets = append(targets, cgCallTarget{rva: target, indirect: false})
			}
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].rva < targets[j].rva })
	return targets
}

// findCallersARM64 scans all executable code for BL instructions targeting funcBeginRVA.
func findCallersARM64(sections []cgSection, targetRVA uint32, imageBase uint64, funcTable []funcRange) []uint32 {
	targetVA := imageBase + uint64(targetRVA)
	seen := make(map[uint32]bool)
	var callers []uint32

	for _, sec := range sections {
		data := sec.data
		for i := 0; i+4 <= len(data); i += 4 {
			instr := binary.LittleEndian.Uint32(data[i:])
			if instr>>26 != 0x25 {
				continue
			}
			instrRVA := sec.rva + uint32(i)
			instrVA := imageBase + uint64(instrRVA)
			imm26 := int32(instr&0x03FFFFFF) << 6 >> 6
			blTarget := instrVA + uint64(int64(imm26)*4)
			if blTarget == targetVA {
				fn := findFunc(funcTable, instrRVA)
				if fn != nil && !seen[fn.begin] {
					seen[fn.begin] = true
					callers = append(callers, fn.begin)
				}
			}
		}
	}
	sort.Slice(callers, func(i, j int) bool { return callers[i] < callers[j] })
	return callers
}

// findCallersARM32 scans all executable code for BL instructions targeting funcBeginRVA.
func findCallersARM32(sections []cgSection, targetRVA uint32, imageBase uint64, funcTable []funcRange) []uint32 {
	targetVA := imageBase + uint64(targetRVA)
	seen := make(map[uint32]bool)
	var callers []uint32

	for _, sec := range sections {
		data := sec.data
		for i := 0; i+4 <= len(data); i += 4 {
			instr := binary.LittleEndian.Uint32(data[i:])
			// Skip cond==0xF: unconditional extension space (BLX)
			if instr>>28 == 0x0F {
				continue
			}
			if (instr>>24)&0x0F != 0x0B {
				continue
			}
			instrRVA := sec.rva + uint32(i)
			instrVA := imageBase + uint64(instrRVA)
			imm24 := int32(instr&0x00FFFFFF) << 8 >> 8
			blTarget := instrVA + 8 + uint64(int64(imm24)*4)
			if blTarget == targetVA {
				fn := findFunc(funcTable, instrRVA)
				if fn != nil && !seen[fn.begin] {
					seen[fn.begin] = true
					callers = append(callers, fn.begin)
				}
			}
		}
	}
	sort.Slice(callers, func(i, j int) bool { return callers[i] < callers[j] })
	return callers
}

