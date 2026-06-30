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

// alignsToX86 reports whether linearly decoding x86 instructions from startOff
// lands exactly on queryOff (an instruction boundary). A misaligned start --
// one pointing into the middle of an instruction or immediate -- either fails to
// decode or steps over queryOff, both returning false. This is the core validity
// test: the true function start decodes cleanly up to the query address.
func alignsToX86(data []byte, startOff, queryOff, mode int) bool {
	if startOff < 0 || queryOff < startOff || queryOff >= len(data) {
		return false
	}
	pos := startOff
	// A real start-to-query span is small; cap iterations defensively so a
	// pathological stream can't spin.
	for i := 0; i < 200000 && pos <= queryOff; i++ {
		if pos == queryOff {
			return true
		}
		inst, err := x86asm.Decode(data[pos:], mode)
		if err != nil || inst.Len == 0 {
			return false
		}
		pos += inst.Len
	}
	return false
}

// execSectionForRVA returns the executable section containing rva and its raw
// data. ok is false if rva is outside every section or lands in a non-code one.
func execSectionForRVA(f *pe.File, rva uint32) (sec *pe.Section, data []byte, ok bool) {
	for _, s := range f.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
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

// refineFuncStart enriches heuristic bounds with an authoritative start when the
// query is covered by an export, and validates the chosen start by alignment.
// bounds may be nil (heuristic found nothing); an export anchor can still produce
// a result. Returns nil only when neither source yields a usable start.
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
	var prevStart, nextStart uint32
	var havePrev, haveNext bool
	for _, s := range starts {
		if s < secRVA || s >= secRVA+uint32(len(secData)) {
			continue
		}
		if s <= queryRVA {
			prevStart, havePrev = s, true
		} else {
			nextStart, haveNext = s, true
			break
		}
	}

	// 1) Export anchor: an export covers the query and its bytes decode cleanly
	//    up to it -> authoritative start.
	if havePrev {
		startOff := int(prevStart - secRVA)
		if alignsToX86(secData, startOff, queryOff, mode) {
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

	// 2) No export anchor -- validate the heuristic start by alignment.
	if bounds == nil {
		return nil
	}
	if bounds.StartRVA < secRVA {
		bounds.StartSource = "heuristic"
		return bounds
	}
	startOff := int(bounds.StartRVA - secRVA)
	if alignsToX86(secData, startOff, queryOff, mode) {
		if matchesPrologue(secData, startOff, mode) {
			bounds.StartSource = "prologue"
			if bounds.Confidence != "low" {
				bounds.Confidence = "medium"
			}
		} else {
			bounds.StartSource = "heuristic"
		}
		return bounds
	}

	// Misaligned: the start does not decode to the query (it points inside an
	// instruction). Flag it instead of presenting a wrong start as authoritative.
	bounds.StartSource = "heuristic-misaligned"
	bounds.Confidence = "low"
	return bounds
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
