package analyze

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"strings"
)

const maxVtableScanResults = 200

// opVtableScan scans PE .rdata for MSVC vtables with valid RTTI.
// For each pointer-aligned slot, checks if the preceding slot contains a valid
// CompleteObjectLocator pointer (signature + pSelf cross-validation for x64).
// Returns all discovered vtables with class names.
func opVtableScan(input AnalyzeInput) (string, error) {
	f, err := pe.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("vtable_scan requires a PE file: %w", err)
	}
	defer f.Close()

	imageBase := peImageBase(f)
	is64 := f.FileHeader.Machine == 0x8664 || f.FileHeader.Machine == 0xaa64
	ptrSize := 4
	if is64 {
		ptrSize = 8
	}

	// Find .rdata section (vtables with RTTI are typically here)
	var rdataSec *pe.Section
	for _, s := range f.Sections {
		name := strings.TrimRight(s.Name, "\x00")
		if name == ".rdata" {
			rdataSec = s
			break
		}
	}
	if rdataSec == nil {
		return "", fmt.Errorf("no .rdata section found (vtables with RTTI are in .rdata)")
	}

	cache := make(secCache)
	secData, err := cachedSectionData(rdataSec, cache)
	if err != nil {
		return "", fmt.Errorf("cannot read .rdata: %w", err)
	}

	rdataRVA := rdataSec.VirtualAddress
	textStart, textEnd := textSectionRange(f)

	type vtableEntry struct {
		va        uint64
		className string
		mangled   string
	}

	var results []vtableEntry

	// Scan .rdata in ptrSize steps.
	// At each position P, check if P-ptrSize holds a valid COL pointer.
	// If so, P is a vtable start and P-ptrSize is the RTTI meta-slot.
	for off := ptrSize; off+ptrSize <= len(secData); off += ptrSize {
		if len(results) >= maxVtableScanResults {
			break
		}

		// Read potential COL pointer from the slot BEFORE current position
		metaOff := off - ptrSize
		var colPtr uint64
		if ptrSize == 8 {
			colPtr = binary.LittleEndian.Uint64(secData[metaOff : metaOff+8])
		} else {
			colPtr = uint64(binary.LittleEndian.Uint32(secData[metaOff : metaOff+4]))
		}

		// Quick filter: must be within PE address space
		if colPtr < imageBase || colPtr == 0 {
			continue
		}
		if colPtr-imageBase > 0xFFFFFFFF {
			continue
		}

		// Also check that the first vtable entry looks like a code pointer
		var firstEntry uint64
		if ptrSize == 8 {
			firstEntry = binary.LittleEndian.Uint64(secData[off : off+8])
		} else {
			firstEntry = uint64(binary.LittleEndian.Uint32(secData[off : off+4]))
		}
		// First vtable entry should point to .text (code)
		if firstEntry < imageBase {
			continue
		}
		if firstEntry-imageBase > 0xFFFFFFFF {
			continue
		}
		entryRVA := uint32(firstEntry - imageBase)
		if textStart == 0 || entryRVA < textStart || entryRVA >= textEnd {
			continue
		}

		// Try to read and validate COL
		col, err := readCOL(f, imageBase, colPtr, is64, cache)
		if err != nil {
			continue
		}

		// x64: cross-validate pSelf
		if is64 {
			colRVA := uint32(colPtr - imageBase)
			if col.pSelf != colRVA {
				continue
			}
		}

		// Read TypeDescriptor name
		var tdVA uint64
		if is64 {
			tdVA = imageBase + uint64(col.pTypeDescriptor)
		} else {
			tdVA = uint64(col.pTypeDescriptor)
		}

		mangled, err := readTypeDescriptorName(f, imageBase, tdVA, ptrSize, cache)
		if err != nil || mangled == "" {
			continue
		}

		// Sanity: name should start with .?A (MSVC mangled type name)
		if !strings.HasPrefix(mangled, ".?A") {
			continue
		}

		vtableVA := imageBase + uint64(rdataRVA) + uint64(off)
		demangled := demangleMSVC(mangled)

		results = append(results, vtableEntry{
			va:        vtableVA,
			className: demangled,
			mangled:   mangled,
		})
	}

	if len(results) == 0 {
		return "No vtables with RTTI found in .rdata.\n\nThis may indicate:\n- No C++ classes with virtual functions\n- RTTI disabled (/GR-)\n- Non-MSVC compiler", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d vtable(s) with RTTI in .rdata (%d-bit):\n\n", len(results), ptrSize*8))
	for i, r := range results {
		if r.className != r.mangled {
			sb.WriteString(fmt.Sprintf("  [%d] 0x%x  %s (%s)\n", i, r.va, r.className, r.mangled))
		} else {
			sb.WriteString(fmt.Sprintf("  [%d] 0x%x  %s\n", i, r.va, r.className))
		}
	}

	if len(results) >= maxVtableScanResults {
		sb.WriteString(fmt.Sprintf("\n(truncated at %d results)", maxVtableScanResults))
	}

	return sb.String(), nil
}

// textSectionRange returns the RVA range of the .text section.
func textSectionRange(f *pe.File) (start, end uint32) {
	for _, s := range f.Sections {
		name := strings.TrimRight(s.Name, "\x00")
		if name == ".text" {
			return s.VirtualAddress, s.VirtualAddress + s.VirtualSize
		}
	}
	return 0, 0
}
