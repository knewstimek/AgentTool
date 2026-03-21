package analyze

import (
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
// Uses .pdata for function boundaries and scans CALL instructions for edges.
// Requires x64 PE with .pdata; x86 PE not supported (no reliable function boundaries).
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

	f, err := pe.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("call_graph requires a PE file: %w", err)
	}
	defer f.Close()

	imageBase := peImageBase(f)
	if rootVA < imageBase {
		return "", fmt.Errorf("va 0x%x is below image base 0x%x", rootVA, imageBase)
	}
	if rootVA-imageBase > 0xFFFFFFFF {
		return "", fmt.Errorf("va 0x%x is too far from image base 0x%x (RVA exceeds 4GB)", rootVA, imageBase)
	}

	is64 := f.FileHeader.Machine == 0x8664
	if !is64 {
		return "", fmt.Errorf("call_graph requires x64 PE (.pdata needed for function boundaries). x86 PE is not supported")
	}

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

	// Build function table from .pdata
	funcTable := buildFuncTable(f, imageBase)
	if len(funcTable) == 0 {
		return "", fmt.Errorf("no .pdata found -- call_graph requires exception table for function boundaries")
	}

	// Build symbol map for name resolution
	symbols := peSymbolMap(f, imageBase)

	// Preload executable section data for CALL scanning
	var execSections []cgSection
	for _, sec := range f.Sections {
		if sec.Characteristics&0x20000000 == 0 { // IMAGE_SCN_MEM_EXECUTE
			continue
		}
		data, err := sec.Data()
		if err != nil || len(data) == 0 {
			continue
		}
		execSections = append(execSections, cgSection{rva: sec.VirtualAddress, data: data})
	}

	// Resolve root function
	rootRVA := uint32(rootVA - imageBase)
	rootFunc := findFunc(funcTable, rootRVA)
	if rootFunc == nil {
		return "", fmt.Errorf("no function found at 0x%x. "+
			"Try function_at with va=\"0x%x\" to find the nearest function", rootVA, rootVA)
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

		// Scan this function's code for CALL targets
		callees := scanCallTargets(execSections, curFn.begin, curFn.end, imageBase, is64)

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
	rootCallers := findCallers(execSections, rootFunc.begin, imageBase, funcTable, is64)

	// Format output
	var sb strings.Builder
	rootName := funcName(imageBase+uint64(rootFunc.begin), symbols)
	sb.WriteString(fmt.Sprintf("Call graph for %s (depth=%d, %d nodes):\n\n", rootName, depth, len(visited)))

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
			if err != nil {
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

			// FF 15 disp32 -- CALL [rip+disp32] (indirect call via IAT)
			if instBytes[0] == 0xFF && inst.Len >= 6 && instBytes[1] == 0x15 {
				disp := int32(binary.LittleEndian.Uint32(instBytes[2:6]))
				target := uint32(int64(instrRVA) + int64(inst.Len) + int64(disp))
				if !seen[target] {
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
			if err != nil {
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

