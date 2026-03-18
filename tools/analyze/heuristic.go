package analyze

import (
	"debug/pe"
)

// Heuristic function boundary detection for PE files without .pdata.
// Scans backward for common prologue patterns and forward for ret + padding.
// Less reliable than .pdata -- results should be marked as heuristic.

// Common x86/x64 prologue patterns (most specific first)
var prologuePatterns = [][]byte{
	{0x55, 0x48, 0x89, 0xE5},       // push rbp; mov rbp, rsp (x64)
	{0x55, 0x8B, 0xEC},             // push ebp; mov ebp, esp (x86)
	{0x48, 0x89, 0x5C, 0x24},       // mov [rsp+XX], rbx (x64 leaf/non-frame)
	{0x48, 0x83, 0xEC},             // sub rsp, imm8 (x64 frameless)
	{0x48, 0x81, 0xEC},             // sub rsp, imm32 (x64 frameless large)
	{0x40, 0x53},                   // push rbx (x64 REX prefix)
	{0x40, 0x55},                   // push rbp (x64 REX prefix)
	{0x40, 0x56},                   // push rsi (x64 REX prefix)
	{0x40, 0x57},                   // push rdi (x64 REX prefix)
	{0x56},                         // push esi/rsi
	{0x57},                         // push edi/rdi
	{0x53},                         // push ebx/rbx
}

// maxBackScan is the maximum number of bytes to scan backward for a prologue.
const maxBackScan = 4096

// maxForwardScan is the maximum number of bytes to scan forward for a ret.
const maxForwardScan = 65536

// heuristicBounds holds the result of heuristic function boundary detection.
type heuristicBounds struct {
	StartFileOff uint32 // file offset of detected function start
	EndFileOff   uint32 // file offset of detected function end (after ret + padding)
	StartRVA     uint32
	EndRVA       uint32
	Confidence   string // "medium" or "low"
}

// heuristicFuncBounds tries to detect function boundaries by scanning for
// prologue/epilogue patterns. queryFileOff is the file offset of the query address.
// secData is the raw section data, secFileOff is the section's file offset.
// Returns nil if no reasonable boundaries can be determined.
func heuristicFuncBounds(secData []byte, secFileOff, secRVA, queryFileOff uint32, mode int) *heuristicBounds {
	if len(secData) == 0 || queryFileOff < secFileOff {
		return nil
	}
	posInSec := int(queryFileOff - secFileOff)
	if posInSec >= len(secData) {
		return nil
	}

	// --- Find function start: scan backward for prologue or boundary ---
	startPos := findPrologueBackward(secData, posInSec, mode)

	// --- Find function end: scan forward for ret + padding ---
	endPos := findEpilogueForward(secData, posInSec, mode)

	if startPos < 0 || endPos < 0 || endPos <= startPos {
		return nil
	}

	confidence := "medium"
	// Lower confidence if we scanned a very long way
	if posInSec-startPos > 2048 || endPos-posInSec > 32768 {
		confidence = "low"
	}

	return &heuristicBounds{
		StartFileOff: secFileOff + uint32(startPos),
		EndFileOff:   secFileOff + uint32(endPos),
		StartRVA:     secRVA + uint32(startPos),
		EndRVA:       secRVA + uint32(endPos),
		Confidence:   confidence,
	}
}

// findPrologueBackward scans backward from pos looking for a function prologue.
// It looks for: (1) known prologue byte patterns, or (2) boundary markers
// (int3/nop padding followed by code start).
func findPrologueBackward(data []byte, pos, mode int) int {
	limit := pos - maxBackScan
	if limit < 0 {
		limit = 0
	}

	// Strategy: scan backward looking for int3(CC) or nop(90) padding,
	// then the first non-padding byte after that is the function start.
	// Also check for known prologue patterns along the way.

	// First, check if pos itself is at a prologue
	if matchesPrologue(data, pos, mode) {
		return pos
	}

	// Scan backward byte by byte
	for i := pos - 1; i >= limit; i-- {
		b := data[i]

		// Found padding boundary (int3 or nop)
		if b == 0xCC || b == 0x90 {
			// Found padding: function starts right after this padding byte.
			// Since we scan backward, 'i' is the padding byte closest to pos.
			funcStart := i + 1
			if funcStart > pos {
				// Query address is inside padding -- skip and keep scanning
				// Jump past this padding block to avoid re-examining same bytes
				for i >= limit && (data[i] == 0xCC || data[i] == 0x90) {
					i--
				}
				continue
			}
			return funcStart
		}

		// Check for ret (C3 or C2 XX XX) which indicates previous function end
		if b == 0xC3 {
			funcStart := i + 1
			if funcStart <= pos {
				return funcStart
			}
		}
		if b == 0xC2 && i+2 < len(data) {
			funcStart := i + 3
			if funcStart <= pos {
				return funcStart
			}
		}
	}

	// Fallback: check if there's a prologue pattern at or near the section start
	for i := limit; i < limit+16 && i < pos; i++ {
		if matchesPrologue(data, i, mode) {
			return i
		}
	}

	return -1
}

// findEpilogueForward scans forward from pos looking for function end.
// Looks for ret (C3/C2) followed by padding (CC/90) or another prologue.
func findEpilogueForward(data []byte, pos, mode int) int {
	limit := pos + maxForwardScan
	if limit > len(data) {
		limit = len(data)
	}

	for i := pos; i < limit; i++ {
		b := data[i]

		// ret
		if b == 0xC3 {
			endPos := i + 1
			// Check what follows: padding or prologue = confident boundary
			if endPos < len(data) {
				next := data[endPos]
				if next == 0xCC || next == 0x90 {
					return endPos
				}
				// Next instruction is another prologue
				if matchesPrologue(data, endPos, mode) {
					return endPos
				}
			}
			// ret at end of section data
			if endPos >= len(data) {
				return endPos
			}
			// ret not followed by padding -- could be mid-function ret
			// (e.g. early return). Keep scanning.
			continue
		}

		// ret imm16
		if b == 0xC2 && i+2 < limit {
			endPos := i + 3
			if endPos < len(data) {
				next := data[endPos]
				if next == 0xCC || next == 0x90 {
					return endPos
				}
				if matchesPrologue(data, endPos, mode) {
					return endPos
				}
			}
			if endPos >= len(data) {
				return endPos
			}
			continue
		}
	}

	return -1
}

// matchesPrologue checks if data at pos matches any known prologue pattern.
func matchesPrologue(data []byte, pos, mode int) bool {
	remaining := len(data) - pos
	if remaining <= 0 {
		return false
	}

	for _, pat := range prologuePatterns {
		if len(pat) > remaining {
			continue
		}
		// Skip x86-only patterns in x64 mode and vice versa
		if mode == 64 && len(pat) == 3 && pat[0] == 0x55 && pat[1] == 0x8B {
			continue // push ebp; mov ebp, esp is x86
		}
		if mode == 32 && len(pat) >= 2 && (pat[0] == 0x48 || pat[0] == 0x40) {
			continue // REX prefix patterns are x64
		}
		match := true
		for j, b := range pat {
			if data[pos+j] != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// heuristicFuncEndOffset is the fallback for pdataFuncEndOffset when .pdata is unavailable.
// Uses heuristic scanning to find the function end from a file offset.
func heuristicFuncEndOffset(f *pe.File, queryFileOff uint32) (uint32, bool) {
	// Find which section contains this offset
	for _, s := range f.Sections {
		secStart := s.Offset
		secEnd := s.Offset + s.Size
		if queryFileOff >= secStart && queryFileOff < secEnd {
			// Only scan executable sections
			if s.Characteristics&0x20000000 == 0 { // IMAGE_SCN_MEM_EXECUTE
				return 0, false
			}
			secData, err := s.Data()
			if err != nil {
				return 0, false
			}
			mode := 64
			if f.FileHeader.Machine == 0x14c {
				mode = 32
			}
			posInSec := int(queryFileOff - secStart)
			endPos := findEpilogueForward(secData, posInSec, mode)
			if endPos > 0 {
				return secStart + uint32(endPos), true
			}
			return 0, false
		}
	}
	return 0, false
}

// heuristicFuncBoundsFromPE opens a PE file and runs heuristic detection for a given RVA.
func heuristicFuncBoundsFromPE(f *pe.File, imageBase uint64, queryRVA uint32) *heuristicBounds {
	queryFileOff, _, err := rvaToFileOffset(f, queryRVA)
	if err != nil {
		return nil
	}

	mode := 64
	if f.FileHeader.Machine == 0x14c {
		mode = 32
	}

	// Find the executable section containing this RVA
	for _, s := range f.Sections {
		secStart := s.Offset
		secEnd := s.Offset + s.Size
		if queryFileOff >= secStart && queryFileOff < secEnd {
			if s.Characteristics&0x20000000 == 0 {
				return nil
			}
			secData, err := s.Data()
			if err != nil {
				return nil
			}
			bounds := heuristicFuncBounds(secData, secStart, s.VirtualAddress, queryFileOff, mode)
			if bounds != nil {
				// Adjust RVA to include imageBase for display
				return bounds
			}
			return nil
		}
	}
	return nil
}

// peHasPdata checks if a PE file has a valid .pdata (Exception Table).
func peHasPdata(f *pe.File) bool {
	oh64, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || len(oh64.DataDirectory) <= 3 {
		return false
	}
	exc := oh64.DataDirectory[3]
	return exc.VirtualAddress != 0 && exc.Size >= 12
}

// pdataOrHeuristicEndOffset tries .pdata first, then falls back to heuristic.
// Returns (endFileOff, isHeuristic, found).
func pdataOrHeuristicEndOffset(f *pe.File, rva uint32, fileOff uint32) (uint32, bool, bool) {
	// Try .pdata first (reliable, x64 only)
	if endOff, ok := pdataFuncEndOffset(f, rva); ok {
		return endOff, false, true
	}
	// Fallback: heuristic scanning
	if endOff, ok := heuristicFuncEndOffset(f, fileOff); ok {
		return endOff, true, true
	}
	return 0, false, false
}

// peExecSectionContaining returns the section data and section info for the section
// containing the given file offset, only if it's executable.
func peExecSectionData(f *pe.File, fileOff uint32) ([]byte, *pe.Section) {
	for _, s := range f.Sections {
		if fileOff >= s.Offset && fileOff < s.Offset+s.Size {
			if s.Characteristics&0x20000000 == 0 {
				return nil, nil
			}
			data, err := s.Data()
			if err != nil {
				return nil, nil
			}
			return data, s
		}
	}
	return nil, nil
}

// readSectionDataAt reads section data surrounding a file offset.
// Used for backward scanning (need data before the query point).
func readSectionDataAt(f *pe.File, fileOff uint32) (data []byte, secFileOff uint32, secRVA uint32, ok bool) {
	for _, s := range f.Sections {
		if fileOff >= s.Offset && fileOff < s.Offset+s.Size {
			if s.Characteristics&0x20000000 == 0 {
				return nil, 0, 0, false
			}
			d, err := s.Data()
			if err != nil {
				return nil, 0, 0, false
			}
			// Section data from pe.Section.Data() starts at VirtualAddress=0 offset within section.
			// But the raw file data starts at s.Offset.
			// For our file-offset based scanning, section data maps to [s.Offset, s.Offset+len(d))
			return d, s.Offset, s.VirtualAddress, true
		}
	}
	return nil, 0, 0, false
}

// sectionForRVA maps an RVA to the section that contains it, useful for
// displaying which section a heuristic boundary falls in.
func sectionNameForRVA(f *pe.File, rva uint32) string {
	for _, s := range f.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
			return s.Name
		}
	}
	return ""
}

// imageBaseAndMode extracts common PE info needed by heuristic callers.
func imageBaseAndMode(f *pe.File) (uint64, int) {
	ib := peImageBase(f)
	mode := 64
	if f.FileHeader.Machine == 0x14c {
		mode = 32
	}
	return ib, mode
}

// FormatConfidenceWarning returns a warning string for heuristic results.
func formatHeuristicWarning(confidence string) string {
	switch confidence {
	case "low":
		return "  ** Heuristic detection (low confidence) -- boundaries may be inaccurate **\n"
	default:
		return "  ** Heuristic detection (no .pdata) -- boundaries may be inaccurate **\n"
	}
}
