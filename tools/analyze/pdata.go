package analyze

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"
)

// runtimeFunction represents a .pdata entry (RUNTIME_FUNCTION, 12 bytes).
// x64 PE only -- contains function start/end RVAs and unwind info pointer.
type runtimeFunction struct {
	BeginAddress uint32
	EndAddress   uint32
	UnwindData   uint32
}

// pdataFuncEndOffset looks up .pdata for the function containing queryRVA
// and returns the file offset of the function's end address.
// Returns (0, false) if not found or not applicable (x86, no .pdata, etc.)
func pdataFuncEndOffset(f *pe.File, queryRVA uint32) (uint32, bool) {
	oh64, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || len(oh64.DataDirectory) <= 3 {
		return 0, false
	}
	excDir := oh64.DataDirectory[3]
	if excDir.VirtualAddress == 0 || excDir.Size == 0 {
		return 0, false
	}
	if excDir.Size < 12 {
		return 0, false
	}

	// Read .pdata via section data
	var pdataData []byte
	for _, s := range f.Sections {
		if excDir.VirtualAddress >= s.VirtualAddress &&
			excDir.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			secData, err := s.Data()
			if err != nil {
				return 0, false
			}
			off := excDir.VirtualAddress - s.VirtualAddress
			if uint64(off) >= uint64(len(secData)) {
				return 0, false // .pdata offset beyond section raw data
			}
			end := off + excDir.Size
			if int(end) > len(secData) {
				end = uint32(len(secData))
			}
			pdataData = secData[off:end]
			break
		}
	}
	if len(pdataData) < 12 {
		return 0, false
	}

	actualEntries := uint32(len(pdataData)) / 12

	// Binary search: entries sorted by BeginAddress
	lo, hi := uint32(0), actualEntries
	for lo < hi {
		mid := lo + (hi-lo)/2
		off := mid * 12
		begin := binary.LittleEndian.Uint32(pdataData[off:])
		if begin > queryRVA {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	if lo == 0 {
		return 0, false
	}
	idx := lo - 1
	off := idx * 12
	begin := binary.LittleEndian.Uint32(pdataData[off:])
	endRVA := binary.LittleEndian.Uint32(pdataData[off+4:])

	if begin >= endRVA || queryRVA < begin || queryRVA >= endRVA {
		return 0, false
	}

	// Convert end RVA to file offset
	endFileOff, _, err := rvaToFileOffset(f, endRVA)
	if err != nil {
		return 0, false
	}
	return endFileOff, true
}

// opFunctionAt finds the function containing a given VA using .pdata (Exception Table).
// Only works with x64 PE files that have a .pdata section.
func opFunctionAt(input AnalyzeInput) (string, error) {
	vaStr := input.VA
	if vaStr == "" && input.TargetVA != "" {
		vaStr = input.TargetVA
	}
	if vaStr == "" {
		return "", fmt.Errorf("va is required for function_at")
	}

	va, err := parseHexAddr(vaStr)
	if err != nil {
		return "", fmt.Errorf("invalid va: %s", vaStr)
	}

	f, err := pe.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("function_at requires a PE file: %w", err)
	}
	defer f.Close()

	imageBase := peImageBase(f)
	if va < imageBase {
		return "", fmt.Errorf("va 0x%x is below image base 0x%x", va, imageBase)
	}
	if va-imageBase > 0xFFFFFFFF {
		return "", fmt.Errorf("va 0x%x is too far from image base 0x%x (RVA exceeds 4GB)", va, imageBase)
	}
	queryRVA := uint32(va - imageBase)

	// Try .pdata first (x64 only), fall back to heuristic for x86 or stripped binaries
	usePdata := peHasPdata(f)
	if !usePdata {
		// No .pdata available -- use heuristic detection
		bounds := heuristicFuncBoundsFromPE(f, imageBase, queryRVA)
		if bounds == nil {
			if f.FileHeader.Machine == 0x14c {
				return "", fmt.Errorf("function_at: no .pdata (x86 PE) and heuristic detection failed for 0x%x. "+
					"Try using disassemble with va=\"0x%x\" instead -- it will show instructions from that address "+
					"and you can identify the function boundary by looking for ret (C3) followed by int3/nop padding", va, va)
			}
			return "", fmt.Errorf("function_at: no .pdata (x64 PE, possibly stripped) and heuristic detection failed for 0x%x. "+
				"Try using disassemble with va=\"0x%x\" instead -- it will show instructions from that address "+
				"and you can identify the function boundary by looking for ret (C3) followed by int3/nop padding", va, va)
		}
		return formatHeuristicResult(f, imageBase, va, bounds, input)
	}

	var excDir pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 3 {
			excDir = oh.DataDirectory[3]
		}
	default:
		return "", fmt.Errorf("PE file has no optional header")
	}

	if excDir.VirtualAddress == 0 || excDir.Size == 0 {
		return "", fmt.Errorf("no .pdata section (Exception Table not present)")
	}

	// Each RUNTIME_FUNCTION entry is 12 bytes
	entryCount := excDir.Size / 12
	if entryCount == 0 {
		return "", fmt.Errorf(".pdata is empty (size=%d)", excDir.Size)
	}
	// Sanity limit: prevent OOM from malformed PE with huge .pdata size
	const maxPdataEntries = 500000 // ~6MB, enough for any real binary
	if entryCount > maxPdataEntries {
		entryCount = maxPdataEntries
	}

	fileOff, _, err := rvaToFileOffset(f, excDir.VirtualAddress)
	if err != nil {
		return "", fmt.Errorf("cannot locate .pdata: %w", err)
	}

	// Read .pdata raw bytes (use int to avoid uint32 overflow in multiplication)
	pdataSize := int(entryCount) * 12
	pdataData := make([]byte, pdataSize)

	fh, err := os.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("cannot open file: %w", err)
	}
	defer fh.Close()

	n, err := fh.ReadAt(pdataData, int64(fileOff))
	if err != nil && n == 0 {
		return "", fmt.Errorf("cannot read .pdata: %w", err)
	}
	pdataData = pdataData[:n]
	actualEntries := uint32(n) / 12

	// Parse RUNTIME_FUNCTION entries
	entries := make([]runtimeFunction, 0, actualEntries)
	for i := uint32(0); i < actualEntries; i++ {
		off := i * 12
		entry := runtimeFunction{
			BeginAddress: binary.LittleEndian.Uint32(pdataData[off:]),
			EndAddress:   binary.LittleEndian.Uint32(pdataData[off+4:]),
			UnwindData:   binary.LittleEndian.Uint32(pdataData[off+8:]),
		}
		// Skip corrupted entries
		if entry.BeginAddress >= entry.EndAddress {
			continue
		}
		entries = append(entries, entry)
	}

	if len(entries) == 0 {
		return "", fmt.Errorf(".pdata has no valid entries")
	}

	// Binary search: .pdata entries are sorted by BeginAddress
	idx := sort.Search(len(entries), func(i int) bool {
		return entries[i].BeginAddress > queryRVA
	})
	idx-- // step back to the entry that could contain queryRVA

	if idx < 0 {
		nearest := entries[0]
		return "", fmt.Errorf("address 0x%x is before all .pdata functions (first function starts at 0x%x). "+
			"This address may be in a jump stub or padding area. Try function_at with va=\"0x%x\" instead",
			va, imageBase+uint64(nearest.BeginAddress), imageBase+uint64(nearest.BeginAddress))
	}

	entry := entries[idx]
	if queryRVA < entry.BeginAddress || queryRVA >= entry.EndAddress {
		// Not inside this function -- provide nearest entries and actionable guidance
		msg := fmt.Sprintf("address 0x%x is between .pdata functions", va)
		msg += fmt.Sprintf(" (prev: 0x%x-0x%x",
			imageBase+uint64(entry.BeginAddress), imageBase+uint64(entry.EndAddress))
		if idx+1 < len(entries) {
			next := entries[idx+1]
			msg += fmt.Sprintf(", next: 0x%x-0x%x). ", imageBase+uint64(next.BeginAddress), imageBase+uint64(next.EndAddress))
			msg += fmt.Sprintf("Try function_at with va=\"0x%x\" or va=\"0x%x\" for the neighboring functions",
				imageBase+uint64(entry.BeginAddress), imageBase+uint64(next.BeginAddress))
		} else {
			msg += "). "
			msg += fmt.Sprintf("Try function_at with va=\"0x%x\" for the previous function",
				imageBase+uint64(entry.BeginAddress))
		}
		return "", fmt.Errorf("%s", msg)
	}

	funcSize := entry.EndAddress - entry.BeginAddress
	funcStartVA := imageBase + uint64(entry.BeginAddress)
	funcEndVA := imageBase + uint64(entry.EndAddress)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Function containing 0x%x:\n", va))
	sb.WriteString(fmt.Sprintf("  Start:  0x%x (RVA: 0x%x)\n", funcStartVA, entry.BeginAddress))
	sb.WriteString(fmt.Sprintf("  End:    0x%x (RVA: 0x%x)\n", funcEndVA, entry.EndAddress))
	sb.WriteString(fmt.Sprintf("  Size:   %d bytes\n", funcSize))
	sb.WriteString(fmt.Sprintf("  Unwind: RVA 0x%x\n", entry.UnwindData))
	sb.WriteString(fmt.Sprintf("  .pdata: %d total entries\n", len(entries)))

	// Auto-disassemble the function
	count := input.Count
	if count <= 0 {
		count = defaultDisasmCount
	}
	if count > maxDisasmCount {
		count = maxDisasmCount
	}

	funcFileOff, _, err := rvaToFileOffset(f, entry.BeginAddress)
	if err == nil {
		disasmInput := AnalyzeInput{
			FilePath: input.FilePath,
			Offset:   int(funcFileOff),
			Count:    count,
			Mode:     64,
			Arch:     "x86",
			VA:       fmt.Sprintf("0x%x", funcStartVA),
		}

		disasm, disErr := opDisassemble(disasmInput)
		if disErr == nil {
			sb.WriteString(fmt.Sprintf("\nDisassembly (first %d instructions):\n", count))
			for _, line := range strings.Split(disasm, "\n") {
				if line != "" {
					sb.WriteString("  " + line + "\n")
				}
			}
		}
	}

	return sb.String(), nil
}

// formatHeuristicResult formats function_at output when using heuristic detection.
func formatHeuristicResult(f *pe.File, imageBase, va uint64, bounds *heuristicBounds, input AnalyzeInput) (string, error) {
	funcStartVA := imageBase + uint64(bounds.StartRVA)
	funcEndVA := imageBase + uint64(bounds.EndRVA)
	funcSize := bounds.EndRVA - bounds.StartRVA

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Function containing 0x%x:\n", va))
	sb.WriteString(fmt.Sprintf("  Start:  0x%x (RVA: 0x%x)\n", funcStartVA, bounds.StartRVA))
	sb.WriteString(fmt.Sprintf("  End:    0x%x (RVA: 0x%x)\n", funcEndVA, bounds.EndRVA))
	sb.WriteString(fmt.Sprintf("  Size:   %d bytes\n", funcSize))
	sb.WriteString(formatHeuristicWarning(bounds.Confidence))

	// Auto-disassemble
	count := input.Count
	if count <= 0 {
		count = defaultDisasmCount
	}
	if count > maxDisasmCount {
		count = maxDisasmCount
	}

	mode := 64
	if f.FileHeader.Machine == 0x14c {
		mode = 32
	}

	disasmInput := AnalyzeInput{
		FilePath: input.FilePath,
		Offset:   int(bounds.StartFileOff),
		Count:    count,
		Mode:     mode,
		Arch:     "x86",
		VA:       fmt.Sprintf("0x%x", funcStartVA),
	}

	disasm, disErr := opDisassemble(disasmInput)
	if disErr == nil {
		sb.WriteString(fmt.Sprintf("\nDisassembly (first %d instructions):\n", count))
		for _, line := range strings.Split(disasm, "\n") {
			if line != "" {
				sb.WriteString("  " + line + "\n")
			}
		}
	}

	return sb.String(), nil
}
