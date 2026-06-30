package analyze

// Export-anchored function-start resolution for PE files without .pdata.
//
// Without an exception table (32-bit PE, or stripped x64), function_at falls
// back to scanning for prologue/epilogue bytes. That scan can lock onto a byte
// that merely *looks* like padding (e.g. a 0x90 inside an immediate operand),
// returning a start that points into the middle of an instruction -- which then
// disassembles to a bogus `db 0xNN` and gets believed as ground truth.
//
// Two defenses live here:
//  1. Export table as ground truth: an exported function RVA is an authoritative
//     start. If the query falls within [export, nextExport) and the bytes decode
//     cleanly from that export up to the query, the export is the real start.
//  2. Alignment validation: any candidate start is only trusted if linearly
//     decoding from it lands exactly on the query address. A start that fails
//     this is flagged misaligned with low confidence instead of being presented
//     as correct.

import (
	"debug/pe"
	"sort"

	"golang.org/x/arch/x86/x86asm"
)

const (
	imageScnMemExecute = 0x20000000
	imageScnCntCode    = 0x00000020
)

// functionContains reports whether queryOff is reachable from startOff by a
// bounded, CFG-respecting traversal that stays inside a single function. It
// follows fallthrough and direct (relative) branch targets, stops at returns,
// indirect/unconditional branches and undecodable bytes, and treats every OTHER
// known function start as a wall. This is a sound-ish containment proof.
//
// A plain linear sweep is NOT sound: a RET followed immediately by the next
// function's prologue (no int3/nop gap), a tail-call JMP, a noreturn CALL, or an
// inline jump table would all let the sweep walk into a neighbouring function
// and "reach" a query that does not belong to startOff -- producing a confident
// wrong answer (advisor-flagged). Traversal stops at those control-flow edges.
//
// otherStarts holds every known function start except the seed; reaching one
// means we crossed into a different function, so that path is abandoned.
func functionContains(data []byte, startOff, queryOff, mode int, otherStarts map[int]bool) bool {
	if startOff < 0 || queryOff < startOff || queryOff >= len(data) {
		return false
	}
	visited := make(map[int]bool)
	stack := []int{startOff}
	for len(stack) > 0 && len(visited) < 60000 {
		pos := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if pos < 0 || pos >= len(data) || visited[pos] {
			continue
		}
		// Another function's start is a hard wall (the seed itself excepted).
		if pos != startOff && otherStarts[pos] {
			continue
		}
		if pos == queryOff {
			return true
		}
		visited[pos] = true

		inst, err := x86asm.Decode(data[pos:], mode)
		if err != nil || inst.Len == 0 {
			continue // dead path: undecodable bytes are not a valid continuation
		}
		next := pos + inst.Len
		switch inst.Op {
		case x86asm.RET, x86asm.LRET, x86asm.IRET, x86asm.IRETD, x86asm.IRETQ:
			// terminator: no fallthrough
		case x86asm.JMP:
			// Unconditional jump: only the direct target continues (no fallthrough).
			// Indirect (jump table / register) targets are unknown -> stop.
			if t, ok := branchTargetOff(inst, pos); ok {
				stack = append(stack, t)
			}
		case x86asm.CALL, x86asm.LCALL:
			// Assume the call returns: continue at the fallthrough. (Calls to
			// noreturn targets are a known minor blind spot -- they need a name list.)
			stack = append(stack, next)
		default:
			// Conditional branch (Jcc/LOOP/JCXZ): both target and fallthrough.
			// Anything else: plain fallthrough.
			if t, ok := branchTargetOff(inst, pos); ok {
				stack = append(stack, t)
			}
			stack = append(stack, next)
		}
	}
	return false
}

// branchTargetOff returns the section-relative offset of a direct (PC-relative)
// branch's target, or ok=false for indirect branches (register/memory operands).
func branchTargetOff(inst x86asm.Inst, pos int) (int, bool) {
	if len(inst.Args) == 0 {
		return 0, false
	}
	rel, ok := inst.Args[0].(x86asm.Rel)
	if !ok {
		return 0, false
	}
	return pos + inst.Len + int(rel), true
}

// execSectionForRVA returns the executable section containing rva and its raw
// data. ok is false if rva is outside every section or lands in a non-code one.
func execSectionForRVA(f *pe.File, rva uint32) (sec *pe.Section, data []byte, ok bool) {
	for _, s := range f.Sections {
		// uint64 comparison avoids a uint32 wrap of VirtualAddress+VirtualSize
		// (a crafted section near the 4GB edge) silently dropping the section.
		if uint64(rva) >= uint64(s.VirtualAddress) && uint64(rva) < uint64(s.VirtualAddress)+uint64(s.VirtualSize) {
			if s.Characteristics&(imageScnMemExecute|imageScnCntCode) == 0 {
				return nil, nil, false
			}
			d, err := s.Data()
			if err != nil {
				return nil, nil, false
			}
			return s, d, true
		}
	}
	return nil, nil, false
}

// codeExportStarts returns exported function RVAs that fall in executable
// sections (real code entry points), sorted ascending, plus an rva->label map.
// Forwarders and data exports (tables/globals in .rdata/.data) are excluded so
// the set is purely function starts.
func codeExportStarts(f *pe.File) ([]uint32, map[uint32]string) {
	exports := parseExports(f)
	if len(exports) == 0 {
		return nil, nil
	}
	labels := make(map[uint32]string)
	var starts []uint32
	for _, e := range exports {
		if e.forwarder {
			continue
		}
		if _, _, ok := execSectionForRVA(f, e.rva); !ok {
			continue // data export, not a code start
		}
		if _, seen := labels[e.rva]; !seen {
			starts = append(starts, e.rva)
		}
		labels[e.rva] = e.displayName()
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })
	return starts, labels
}

// refineFuncStart resolves the start of the function containing queryRVA, using
// the export table as ground truth and a CFG-respecting containment proof to
// keep it sound. bounds is the heuristic guess (may be nil). Returns nil only
// when nothing usable is found.
//
// Confidence policy (advisor-aligned): only an export proven to CONTAIN the
// query via functionContains is "exact". Everything else is an internal,
// non-exported function -- a strong frame-setup prologue is "medium", anything
// weaker or unreachable is "low". Internal starts are never exact/high because
// they are not ground truth.
func refineFuncStart(f *pe.File, queryRVA uint32, bounds *heuristicBounds, mode int) *heuristicBounds {
	sec, secData, ok := execSectionForRVA(f, queryRVA)
	if !ok {
		// Not in a code section -- nothing to validate; report as heuristic.
		if bounds != nil && bounds.StartSource == "" {
			bounds.StartSource = "heuristic"
		}
		return bounds
	}
	secRVA := sec.VirtualAddress
	secFileOff := uint32(sec.Offset)
	queryOff := int(queryRVA - secRVA)

	starts, labels := codeExportStarts(f)
	// Export starts in this section as offsets -- traversal walls: reaching a
	// different exported function means we left the candidate's body.
	exportOffs := make(map[int]bool)
	var prevStart, nextStart uint32
	var havePrev, haveNext bool
	for _, s := range starts {
		if s < secRVA || s >= secRVA+uint32(len(secData)) {
			continue
		}
		exportOffs[int(s-secRVA)] = true
		if s <= queryRVA {
			prevStart, havePrev = s, true
		} else if !haveNext {
			nextStart, haveNext = s, true
		}
	}

	// 1) Export anchor: only the nearest export at/below the query can contain it
	//    (any earlier export's body ends before this one starts). It is
	//    authoritative only if CFG traversal from it actually reaches the query.
	if havePrev {
		startOff := int(prevStart - secRVA)
		if functionContains(secData, startOff, queryOff, mode, exportOffs) {
			end := computeFuncEnd(secData, secRVA, queryOff, bounds, haveNext, nextStart, mode)
			return &heuristicBounds{
				StartFileOff: secFileOff + (prevStart - secRVA),
				EndFileOff:   secFileOff + (end - secRVA),
				StartRVA:     prevStart,
				EndRVA:       end,
				Confidence:   "exact",
				StartSource:  "export",
				StartLabel:   labels[prevStart],
			}
		}
	}

	// 2) Internal (non-exported) function: validate the heuristic start with the
	//    same CFG traversal and label it honestly.
	if bounds == nil {
		return nil
	}
	if bounds.StartRVA < secRVA {
		bounds.StartSource = "heuristic"
		return bounds
	}
	startOff := int(bounds.StartRVA - secRVA)
	if functionContains(secData, startOff, queryOff, mode, exportOffs) {
		if strongPrologue(secData, startOff, mode) {
			bounds.StartSource = "prologue"
			bounds.Confidence = "medium"
		} else {
			// Reaches the query, but a bare single-byte push (or other weak start)
			// is too unreliable to call medium -- it could be mid-function.
			bounds.StartSource = "heuristic"
			bounds.Confidence = "low"
		}
		return bounds
	}

	// The start does not reach the query under CFG traversal: it points inside an
	// instruction or into another function. Flag it, never present it as fact.
	bounds.StartSource = "heuristic-misaligned"
	bounds.Confidence = "low"
	return bounds
}

// strongPrologue reports whether data at off begins with a multi-byte frame-setup
// prologue. Bare single-byte pushes (0x53/0x56/0x57) are deliberately excluded:
// they occur mid-function too often to justify medium confidence (advisor
// guidance). Recognizes the shared multi-byte patterns plus x86 frameless
// "sub esp, imm" (83 EC / 81 EC).
func strongPrologue(data []byte, off, mode int) bool {
	for _, pat := range prologuePatterns {
		if len(pat) < 2 || off+len(pat) > len(data) {
			continue
		}
		match := true
		for k := range pat {
			if data[off+k] != pat[k] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	if mode == 32 && off+2 <= len(data) && (data[off] == 0x83 || data[off] == 0x81) && data[off+1] == 0xEC {
		return true
	}
	return false
}

// computeFuncEnd picks the tightest defensible end for an export-anchored
// function: the heuristic epilogue when available, otherwise a forward ret scan,
// capped at the next export start (a function cannot extend past it).
func computeFuncEnd(secData []byte, secRVA uint32, queryOff int, bounds *heuristicBounds, haveNext bool, nextStart uint32, mode int) uint32 {
	var end uint32
	if bounds != nil && bounds.EndRVA > secRVA {
		end = bounds.EndRVA
	} else if endPos := findEpilogueForward(secData, queryOff, mode); endPos > queryOff {
		end = secRVA + uint32(endPos)
	} else {
		end = secRVA + uint32(len(secData))
	}
	if haveNext && end > nextStart {
		end = nextStart
	}
	return end
}
