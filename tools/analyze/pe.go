package analyze

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// opPEInfo parses PE (Portable Executable) headers and displays
// machine type, image base, entry point, sections, imports, and exports.
func opPEInfo(input AnalyzeInput) (string, error) {
	f, err := pe.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("not a valid PE file: %w", err)
	}
	defer f.Close()

	var sb strings.Builder

	// Machine type
	machineNames := map[uint16]string{
		0x14c:  "i386 (x86)",
		0x8664: "AMD64 (x64)",
		0xaa64: "ARM64",
	}
	machine := f.FileHeader.Machine
	machineName := machineNames[machine]
	if machineName == "" {
		machineName = fmt.Sprintf("0x%x", machine)
	}
	sb.WriteString(fmt.Sprintf("Machine: %s\n", machineName))

	// PE timestamp (build time)
	ts := f.FileHeader.TimeDateStamp
	if ts > 0 {
		t := time.Unix(int64(ts), 0).UTC()
		sb.WriteString(fmt.Sprintf("Timestamp: 0x%08x (%s)\n", ts, t.Format("2006-01-02 15:04:05 UTC")))
	}

	// File header characteristics (decoded)
	sb.WriteString(fmt.Sprintf("Characteristics: 0x%x", f.FileHeader.Characteristics))
	if chFlags := decodeFileCharacteristics(f.FileHeader.Characteristics); chFlags != "" {
		sb.WriteString(fmt.Sprintf(" [%s]", chFlags))
	}
	sb.WriteString("\n")

	// Image base and entry point from optional header
	var imageBase uint64
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
		sb.WriteString(fmt.Sprintf("Image Base: 0x%x\n", oh.ImageBase))
		sb.WriteString(fmt.Sprintf("Entry Point RVA: 0x%x\n", oh.AddressOfEntryPoint))
		sb.WriteString(fmt.Sprintf("Section Alignment: 0x%x\n", oh.SectionAlignment))
		sb.WriteString(fmt.Sprintf("File Alignment: 0x%x\n", oh.FileAlignment))
		sb.WriteString(fmt.Sprintf("Image Size: 0x%x\n", oh.SizeOfImage))
		sb.WriteString(fmt.Sprintf("Subsystem: %s\n", peSubsystemName(oh.Subsystem)))
		// DllCharacteristics — security mitigations
		sb.WriteString(fmt.Sprintf("DllCharacteristics: 0x%x\n", oh.DllCharacteristics))
		decodeDllCharacteristics(oh.DllCharacteristics, &sb)
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
		sb.WriteString(fmt.Sprintf("Image Base: 0x%x\n", oh.ImageBase))
		sb.WriteString(fmt.Sprintf("Entry Point RVA: 0x%x\n", oh.AddressOfEntryPoint))
		sb.WriteString(fmt.Sprintf("Section Alignment: 0x%x\n", oh.SectionAlignment))
		sb.WriteString(fmt.Sprintf("File Alignment: 0x%x\n", oh.FileAlignment))
		sb.WriteString(fmt.Sprintf("Image Size: 0x%x\n", oh.SizeOfImage))
		sb.WriteString(fmt.Sprintf("Subsystem: %s\n", peSubsystemName(oh.Subsystem)))
		// DllCharacteristics — security mitigations
		sb.WriteString(fmt.Sprintf("DllCharacteristics: 0x%x\n", oh.DllCharacteristics))
		decodeDllCharacteristics(oh.DllCharacteristics, &sb)
	}

	// Sections
	filterSection := strings.TrimSpace(input.Section)
	sb.WriteString(fmt.Sprintf("\nSections (%d):\n", len(f.Sections)))
	sb.WriteString(fmt.Sprintf("  %-10s %-12s %-12s %-12s %-12s %s\n",
		"Name", "VirtAddr", "VirtSize", "RawOffset", "RawSize", "Perms"))

	for _, s := range f.Sections {
		name := s.Name
		if filterSection != "" && !strings.EqualFold(name, filterSection) {
			continue
		}
		flags := peSectionFlags(s.Characteristics)
		sb.WriteString(fmt.Sprintf("  %-10s 0x%-10x 0x%-10x 0x%-10x 0x%-10x %s",
			name, s.VirtualAddress, s.VirtualSize,
			s.Offset, s.Size, flags))

		// RWX warning: sections that are both writable and executable are suspicious
		// (common in packed/encrypted binaries, shellcode, or self-modifying code)
		const IMAGE_SCN_MEM_WRITE   = 0x80000000
		const IMAGE_SCN_MEM_EXECUTE = 0x20000000
		if s.Characteristics&IMAGE_SCN_MEM_WRITE != 0 && s.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0 {
			sb.WriteString("  ⚠ W+X")
		}
		sb.WriteString("\n")
	}

	// RVA to file offset conversion if requested
	if input.RVA != "" {
		rvaStr := strings.TrimPrefix(input.RVA, "0x")
		rvaStr = strings.TrimPrefix(rvaStr, "0X")
		rva, err := strconv.ParseUint(rvaStr, 16, 32)
		if err != nil {
			sb.WriteString(fmt.Sprintf("\nInvalid RVA value: %s (expected 32-bit hex, e.g. '0x36A20')\n", input.RVA))
		} else {
			fileOff, secName, err := rvaToFileOffset(f, uint32(rva))
			if err != nil {
				sb.WriteString(fmt.Sprintf("\nRVA 0x%x: %v\n", rva, err))
			} else {
				sb.WriteString(fmt.Sprintf("\nRVA 0x%x → File offset 0x%x (section: %s, runtime addr: 0x%x)\n",
					rva, fileOff, secName, imageBase+rva))
			}
		}
	}

	// Imports with IAT VA -- parse Import Directory for per-function IAT slot addresses
	parseImportsWithIAT(f, imageBase, &sb)

	// Exports (manually parse export directory for DLLs)
	exports := parseExports(f)
	if len(exports) > 0 {
		sb.WriteString(fmt.Sprintf("\nExports (%d):\n", len(exports)))
		shown := 0
		for _, exp := range exports {
			sb.WriteString(fmt.Sprintf("  0x%x  %s\n", exp.rva, exp.name))
			shown++
			if shown >= 200 {
				sb.WriteString(fmt.Sprintf("  ... +%d more\n", len(exports)-shown))
				break
			}
		}
	}

	// Delay imports -- DLLs loaded on first call, not at startup
	parseDelayImports(f, &sb)

	// TLS callbacks -- code that runs before main(), often used for anti-debug
	parseTLSCallbacks(f, imageBase, &sb)

	// Debug directory -- PDB path, GUID, age for symbol server lookups
	parseDebugDirectory(f, &sb)

	// Load config -- SEH, CFG, security cookie
	parseLoadConfig(f, &sb)

	// .pdata function list when section=".pdata" is requested
	if strings.EqualFold(filterSection, ".pdata") {
		parsePdataFunctionList(f, imageBase, &sb)
	}

	// Auto-disassemble entry point when section=".text" is requested
	if strings.EqualFold(filterSection, ".text") {
		parseTextEntryDisasm(f, imageBase, input, &sb)
	}

	return sb.String(), nil
}

// parseTextEntryDisasm auto-disassembles from the entry point when section=".text" is filtered.
func parseTextEntryDisasm(f *pe.File, imageBase uint64, input AnalyzeInput, sb *strings.Builder) {
	var entryRVA uint32
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		entryRVA = oh.AddressOfEntryPoint
	case *pe.OptionalHeader64:
		entryRVA = oh.AddressOfEntryPoint
	}
	if entryRVA == 0 {
		return
	}

	count := input.Count
	if count <= 0 {
		count = 30 // fewer by default for pe_info context
	}
	if count > maxDisasmCount {
		count = maxDisasmCount
	}

	mode := 64
	if f.FileHeader.Machine == 0x14c {
		mode = 32
	}

	fileOff, _, err := rvaToFileOffset(f, entryRVA)
	if err != nil {
		return
	}

	disasmInput := AnalyzeInput{
		FilePath: input.FilePath,
		Offset:   int(fileOff),
		Count:    count,
		Mode:     mode,
		Arch:     "x86",
		VA:       fmt.Sprintf("0x%x", imageBase+uint64(entryRVA)),
	}

	disasm, disErr := opDisassemble(disasmInput)
	if disErr != nil {
		return
	}

	sb.WriteString(fmt.Sprintf("\nEntry Point Disassembly (VA: 0x%x, first %d instructions):\n", imageBase+uint64(entryRVA), count))
	for _, line := range strings.Split(disasm, "\n") {
		if line != "" && !strings.HasPrefix(line, "(") {
			sb.WriteString("  " + line + "\n")
		}
	}
}

// parsePdataFunctionList outputs all RUNTIME_FUNCTION entries from .pdata as a function table.
func parsePdataFunctionList(f *pe.File, imageBase uint64, sb *strings.Builder) {
	oh64, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		sb.WriteString("\n.pdata function table requires x64 PE\n")
		return
	}
	if len(oh64.DataDirectory) <= 3 {
		sb.WriteString("\nNo Exception Table in PE\n")
		return
	}
	excDir := oh64.DataDirectory[3]
	if excDir.VirtualAddress == 0 || excDir.Size == 0 {
		sb.WriteString("\nException Table (.pdata) is empty\n")
		return
	}

	// Find section containing .pdata
	var pdataData []byte
	for _, s := range f.Sections {
		if excDir.VirtualAddress >= s.VirtualAddress &&
			excDir.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			secData, err := s.Data()
			if err != nil {
				sb.WriteString(fmt.Sprintf("\nCannot read .pdata section: %v\n", err))
				return
			}
			off := excDir.VirtualAddress - s.VirtualAddress
			end := off + excDir.Size
			if int(end) > len(secData) {
				end = uint32(len(secData))
			}
			pdataData = secData[off:end]
			break
		}
	}

	entryCount := len(pdataData) / 12
	if entryCount == 0 {
		sb.WriteString("\n.pdata has no entries\n")
		return
	}

	sb.WriteString(fmt.Sprintf("\nFunction Table (.pdata, %d entries):\n", entryCount))
	sb.WriteString(fmt.Sprintf("  %-20s %-20s %-10s %s\n", "Start VA", "End VA", "Size", "Unwind RVA"))

	shown := 0
	const maxShown = 500
	for i := 0; i < entryCount; i++ {
		off := i * 12
		begin := binary.LittleEndian.Uint32(pdataData[off:])
		end := binary.LittleEndian.Uint32(pdataData[off+4:])
		unwind := binary.LittleEndian.Uint32(pdataData[off+8:])

		if begin >= end {
			continue // skip corrupted entries
		}

		size := end - begin
		sb.WriteString(fmt.Sprintf("  0x%-18x 0x%-18x %-10d 0x%x\n",
			imageBase+uint64(begin), imageBase+uint64(end), size, unwind))
		shown++
		if shown >= maxShown {
			sb.WriteString(fmt.Sprintf("  ... truncated at %d entries (total: %d)\n", maxShown, entryCount))
			break
		}
	}
}

// peSectionFlags converts PE section characteristics to a human-readable permission string.
func peSectionFlags(ch uint32) string {
	var parts []string
	if ch&0x40000000 != 0 { // IMAGE_SCN_MEM_READ
		parts = append(parts, "R")
	}
	if ch&0x80000000 != 0 { // IMAGE_SCN_MEM_WRITE
		parts = append(parts, "W")
	}
	if ch&0x20000000 != 0 { // IMAGE_SCN_MEM_EXECUTE
		parts = append(parts, "X")
	}
	if ch&0x00000020 != 0 { // IMAGE_SCN_CNT_CODE
		parts = append(parts, "CODE")
	}
	if ch&0x00000040 != 0 { // IMAGE_SCN_CNT_INITIALIZED_DATA
		parts = append(parts, "DATA")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%x", ch)
	}
	return strings.Join(parts, " ")
}

// rvaToFileOffset converts an RVA to a file offset using section headers.
func rvaToFileOffset(f *pe.File, rva uint32) (uint32, string, error) {
	for _, s := range f.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
			fileOff := rva - s.VirtualAddress + s.Offset
			return fileOff, s.Name, nil
		}
	}
	return 0, "", fmt.Errorf("RVA 0x%x not found in any section", rva)
}

type exportEntry struct {
	name string
	rva  uint32
}

// parseExports reads the PE export directory to list exported functions.
// Go's debug/pe doesn't expose exports, so we parse manually.
func parseExports(f *pe.File) []exportEntry {
	var dataDir pe.DataDirectory

	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 0 {
			dataDir = oh.DataDirectory[0] // IMAGE_DIRECTORY_ENTRY_EXPORT
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 0 {
			dataDir = oh.DataDirectory[0]
		}
	default:
		return nil
	}

	if dataDir.VirtualAddress == 0 || dataDir.Size == 0 {
		return nil
	}

	// Find section containing export directory
	var exportSection *pe.Section
	for _, s := range f.Sections {
		if dataDir.VirtualAddress >= s.VirtualAddress &&
			dataDir.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			exportSection = s
			break
		}
	}
	if exportSection == nil {
		return nil
	}

	sectionData, err := exportSection.Data()
	if err != nil {
		return nil
	}

	// Offset within section
	dirOff := dataDir.VirtualAddress - exportSection.VirtualAddress
	if int(dirOff)+40 > len(sectionData) {
		return nil
	}

	// Parse IMAGE_EXPORT_DIRECTORY (40 bytes)
	numNames := binary.LittleEndian.Uint32(sectionData[dirOff+24:])
	addrOfFunctions := binary.LittleEndian.Uint32(sectionData[dirOff+28:])
	addrOfNames := binary.LittleEndian.Uint32(sectionData[dirOff+32:])
	addrOfOrdinals := binary.LittleEndian.Uint32(sectionData[dirOff+36:])

	// Sanity check: malformed PE can have arbitrarily large numNames,
	// which would cause excessive memory allocation
	if numNames == 0 || numNames > 10000 {
		return nil
	}

	// Guard against uint32 underflow from malformed PE files
	if addrOfFunctions < exportSection.VirtualAddress ||
		addrOfNames < exportSection.VirtualAddress ||
		addrOfOrdinals < exportSection.VirtualAddress {
		return nil
	}
	// Convert RVAs to section-relative offsets
	funcTableOff := addrOfFunctions - exportSection.VirtualAddress
	nameTableOff := addrOfNames - exportSection.VirtualAddress
	ordTableOff := addrOfOrdinals - exportSection.VirtualAddress

	var entries []exportEntry
	for i := uint32(0); i < numNames; i++ {
		// Read name RVA
		nameRVAOff := nameTableOff + i*4
		if int(nameRVAOff)+4 > len(sectionData) {
			break
		}
		nameRVA := binary.LittleEndian.Uint32(sectionData[nameRVAOff:])

		// Look up ordinal from ordinal table, then use it to index function table
		ordOff := ordTableOff + i*2
		if int(ordOff)+2 > len(sectionData) {
			break
		}
		ordinal := binary.LittleEndian.Uint16(sectionData[ordOff:])
		funcRVAOff := funcTableOff + uint32(ordinal)*4
		if int(funcRVAOff)+4 > len(sectionData) {
			break
		}
		funcRVA := binary.LittleEndian.Uint32(sectionData[funcRVAOff:])

		// Read name string — guard underflow
		if nameRVA < exportSection.VirtualAddress {
			continue
		}
		nameOff := nameRVA - exportSection.VirtualAddress
		if int(nameOff) >= len(sectionData) {
			continue
		}
		end := int(nameOff)
		for end < len(sectionData) && sectionData[end] != 0 {
			end++
		}
		name := string(sectionData[nameOff:end])

		entries = append(entries, exportEntry{name: name, rva: funcRVA})
	}

	return entries
}

// parseTLSCallbacks extracts TLS callback addresses from the PE TLS directory
// (DataDirectory[9]). TLS callbacks execute before the entry point, making them
// a common vector for anti-debugging and anti-tampering code.
func parseTLSCallbacks(f *pe.File, imageBase uint64, sb *strings.Builder) {
	var tlsDir pe.DataDirectory
	var is64 bool
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 9 {
			tlsDir = oh.DataDirectory[9]
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 9 {
			tlsDir = oh.DataDirectory[9]
		}
		is64 = true
	}

	if tlsDir.VirtualAddress == 0 || tlsDir.Size == 0 {
		return
	}

	// Find section containing TLS directory
	var sec *pe.Section
	for _, s := range f.Sections {
		if tlsDir.VirtualAddress >= s.VirtualAddress &&
			tlsDir.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			sec = s
			break
		}
	}
	if sec == nil {
		return
	}

	secData, err := sec.Data()
	if err != nil {
		return
	}

	dirOff := tlsDir.VirtualAddress - sec.VirtualAddress

	// IMAGE_TLS_DIRECTORY32/64: callback array pointer is at offset 12 (32-bit) or 24 (64-bit)
	var callbacksVA uint64
	if is64 {
		if int(dirOff)+40 > len(secData) {
			return
		}
		callbacksVA = binary.LittleEndian.Uint64(secData[dirOff+24:])
	} else {
		if int(dirOff)+24 > len(secData) {
			return
		}
		callbacksVA = uint64(binary.LittleEndian.Uint32(secData[dirOff+12:]))
	}

	if callbacksVA == 0 {
		return
	}

	// Convert VA to RVA, then find in sections
	if callbacksVA < imageBase {
		return
	}
	callbacksRVA := uint32(callbacksVA - imageBase)
	var cbSec *pe.Section
	for _, s := range f.Sections {
		if callbacksRVA >= s.VirtualAddress &&
			callbacksRVA < s.VirtualAddress+s.VirtualSize {
			cbSec = s
			break
		}
	}
	if cbSec == nil {
		return
	}

	cbData, err := cbSec.Data()
	if err != nil {
		return
	}

	cbOff := callbacksRVA - cbSec.VirtualAddress

	// Read callback addresses until null terminator
	var callbacks []uint64
	ptrSize := 4
	if is64 {
		ptrSize = 8
	}

	for i := 0; i < 100; i++ { // safety limit
		off := int(cbOff) + i*ptrSize
		if off+ptrSize > len(cbData) {
			break
		}
		var addr uint64
		if is64 {
			addr = binary.LittleEndian.Uint64(cbData[off:])
		} else {
			addr = uint64(binary.LittleEndian.Uint32(cbData[off:]))
		}
		if addr == 0 {
			break
		}
		callbacks = append(callbacks, addr)
	}

	if len(callbacks) == 0 {
		return
	}

	sb.WriteString(fmt.Sprintf("\n⚠ TLS Callbacks (%d) — execute before main():\n", len(callbacks)))
	for i, cb := range callbacks {
		if cb < imageBase {
			sb.WriteString(fmt.Sprintf("  [%d] VA: 0x%x (invalid: below image base)\n", i, cb))
			continue
		}
		rva := cb - imageBase
		sb.WriteString(fmt.Sprintf("  [%d] VA: 0x%x (RVA: 0x%x)\n", i, cb, rva))
	}
}

// parseDebugDirectory extracts PE debug directory entries (DataDirectory[6]).
// The most important is CodeView (type 2) which contains PDB path, GUID, and age
// needed for downloading matching symbols from a symbol server.
func parseDebugDirectory(f *pe.File, sb *strings.Builder) {
	var debugDir pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 6 {
			debugDir = oh.DataDirectory[6]
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 6 {
			debugDir = oh.DataDirectory[6]
		}
	}

	if debugDir.VirtualAddress == 0 || debugDir.Size == 0 {
		return
	}

	// Find section containing debug directory
	var sec *pe.Section
	for _, s := range f.Sections {
		if debugDir.VirtualAddress >= s.VirtualAddress &&
			debugDir.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			sec = s
			break
		}
	}
	if sec == nil {
		return
	}

	secData, err := sec.Data()
	if err != nil {
		return
	}

	dirOff := debugDir.VirtualAddress - sec.VirtualAddress

	// Each IMAGE_DEBUG_DIRECTORY is 28 bytes
	numEntries := debugDir.Size / 28
	if numEntries > 20 { // sanity limit
		numEntries = 20
	}

	debugTypeNames := map[uint32]string{
		0:  "UNKNOWN",
		1:  "COFF",
		2:  "CODEVIEW",
		3:  "FPO",
		4:  "MISC",
		5:  "EXCEPTION",
		6:  "FIXUP",
		7:  "OMAP_TO_SRC",
		8:  "OMAP_FROM_SRC",
		9:  "BORLAND",
		10: "RESERVED10",
		11: "CLSID",
		12: "VC_FEATURE",
		13: "POGO",
		14: "ILTCG",
		16: "REPRO",
	}

	sb.WriteString(fmt.Sprintf("\nDebug Directory (%d entries):\n", numEntries))

	for i := uint32(0); i < numEntries; i++ {
		entryOff := dirOff + i*28
		if int(entryOff)+28 > len(secData) {
			break
		}

		debugType := binary.LittleEndian.Uint32(secData[entryOff+12:])
		sizeOfData := binary.LittleEndian.Uint32(secData[entryOff+16:])
		// addressOfRawData is RVA, pointerToRawData is file offset
		pointerToRawData := binary.LittleEndian.Uint32(secData[entryOff+24:])

		typeName := debugTypeNames[debugType]
		if typeName == "" {
			typeName = fmt.Sprintf("Type_%d", debugType)
		}

		sb.WriteString(fmt.Sprintf("  [%d] %s (size: %d, file offset: 0x%x)\n",
			i, typeName, sizeOfData, pointerToRawData))

		// Parse CodeView data for PDB info
		if debugType == 2 && sizeOfData > 24 {
			parseCodeView(f, sec, pointerToRawData, sizeOfData, sb)
		}

		// Parse REPRO (deterministic build hash)
		if debugType == 16 && sizeOfData > 0 {
			sb.WriteString("       (Deterministic/reproducible build)\n")
		}
	}
}

// parseCodeView extracts PDB path, GUID, and age from a CodeView debug entry.
// Format: "RSDS" signature (4) + GUID (16) + Age (4) + PDB path (null-terminated).
func parseCodeView(f *pe.File, debugSec *pe.Section, fileOffset, size uint32, sb *strings.Builder) {
	if size > 1024 {
		size = 1024 // PDB path shouldn't be this long
	}

	// CodeView data might be in a different section than the debug directory,
	// so find it by file offset
	for _, s := range f.Sections {
		if fileOffset >= s.Offset && fileOffset < s.Offset+s.Size {
			secData, err := s.Data()
			if err != nil {
				return
			}
			off := fileOffset - s.Offset
			if int(off)+24 > len(secData) {
				return
			}

			sig := string(secData[off : off+4])
			if sig != "RSDS" {
				sb.WriteString(fmt.Sprintf("       CodeView signature: %q (not RSDS)\n", sig))
				return
			}

			// GUID: 16 bytes (4-2-2-8 format)
			guidData := secData[off+4 : off+20]
			d1 := binary.LittleEndian.Uint32(guidData[0:4])
			d2 := binary.LittleEndian.Uint16(guidData[4:6])
			d3 := binary.LittleEndian.Uint16(guidData[6:8])

			sb.WriteString(fmt.Sprintf("       GUID: %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
				d1, d2, d3,
				guidData[8], guidData[9], guidData[10], guidData[11],
				guidData[12], guidData[13], guidData[14], guidData[15]))

			age := binary.LittleEndian.Uint32(secData[off+20:])
			sb.WriteString(fmt.Sprintf("       Age: %d\n", age))

			// PDB path (null-terminated string after age, capped at 260 chars like MAX_PATH)
			pdbStart := off + 24
			pdbEnd := pdbStart
			pdbLimit := pdbStart + 260
			if int(pdbLimit) > len(secData) {
				pdbLimit = uint32(len(secData))
			}
			for pdbEnd < pdbLimit && secData[pdbEnd] != 0 {
				pdbEnd++
			}
			if pdbEnd > pdbStart {
				pdbPath := string(secData[pdbStart:pdbEnd])
				sb.WriteString(fmt.Sprintf("       PDB: %s\n", pdbPath))

				// Show symbol server download URL hint
				guidHex := fmt.Sprintf("%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
					d1, d2, d3,
					guidData[8], guidData[9], guidData[10], guidData[11],
					guidData[12], guidData[13], guidData[14], guidData[15])
				// Extract just filename from PDB path
				pdbName := pdbPath
				for i := len(pdbPath) - 1; i >= 0; i-- {
					if pdbPath[i] == '\\' || pdbPath[i] == '/' {
						pdbName = pdbPath[i+1:]
						break
					}
				}
				sb.WriteString(fmt.Sprintf("       Symbol Server: %s/%s%d/%s\n",
					pdbName, guidHex, age, pdbName))
			}
			return
		}
	}
}

// decodeFileCharacteristics converts PE FileHeader.Characteristics to flag names.
func decodeFileCharacteristics(ch uint16) string {
	type chFlag struct {
		mask uint16
		name string
	}
	flags := []chFlag{
		{0x0001, "RELOCS_STRIPPED"},
		{0x0002, "EXECUTABLE_IMAGE"},
		{0x0020, "LARGE_ADDRESS_AWARE"},
		{0x0100, "32BIT_MACHINE"},
		{0x0200, "DEBUG_STRIPPED"},
		{0x1000, "SYSTEM"},
		{0x2000, "DLL"},
	}
	var parts []string
	for _, fl := range flags {
		if ch&fl.mask != 0 {
			parts = append(parts, fl.name)
		}
	}
	return strings.Join(parts, ", ")
}

// decodeDllCharacteristics shows security mitigations from OptionalHeader.DllCharacteristics.
// This is the PE equivalent of Linux's "checksec".
func decodeDllCharacteristics(ch uint16, sb *strings.Builder) {
	type mitigation struct {
		mask    uint16
		name    string
		present string // shown when flag IS set
		absent  string // shown when flag is NOT set (empty = don't show)
	}
	checks := []mitigation{
		{0x0020, "HIGH_ENTROPY_VA", "High Entropy ASLR", ""},
		{0x0040, "DYNAMIC_BASE", "ASLR", "⚠ No ASLR"},
		{0x0080, "FORCE_INTEGRITY", "Force Integrity", ""},
		{0x0100, "NX_COMPAT", "DEP/NX", "⚠ No DEP"},
		{0x0200, "NO_ISOLATION", "No Isolation", ""},
		{0x0400, "NO_SEH", "No SEH", ""},
		{0x0800, "NO_BIND", "No Bind", ""},
		{0x1000, "APPCONTAINER", "AppContainer", ""},
		{0x4000, "GUARD_CF", "Control Flow Guard", ""},
		{0x8000, "TERMINAL_SERVER_AWARE", "Terminal Server Aware", ""},
	}

	var enabled []string
	var warnings []string
	for _, c := range checks {
		if ch&c.mask != 0 {
			enabled = append(enabled, c.present)
		} else if c.absent != "" {
			warnings = append(warnings, c.absent)
		}
	}

	if len(enabled) > 0 {
		sb.WriteString(fmt.Sprintf("  Mitigations: %s\n", strings.Join(enabled, ", ")))
	}
	for _, w := range warnings {
		sb.WriteString(fmt.Sprintf("  %s\n", w))
	}
}

func peSubsystemName(ss uint16) string {
	names := map[uint16]string{
		0:  "Unknown",
		1:  "Native",
		2:  "Windows GUI",
		3:  "Windows CUI (Console)",
		5:  "OS/2 CUI",
		7:  "POSIX CUI",
		9:  "Windows CE GUI",
		10: "EFI Application",
		11: "EFI Boot Service Driver",
		12: "EFI Runtime Driver",
		13: "EFI ROM",
		14: "Xbox",
		16: "Windows Boot Application",
	}
	if name, ok := names[ss]; ok {
		return name
	}
	return fmt.Sprintf("0x%x", ss)
}

// parseDelayImports extracts delay-loaded DLL names from DataDirectory[13].
// Delay imports are resolved on first call rather than at load time.
func parseDelayImports(f *pe.File, sb *strings.Builder) {
	var delayDir pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 13 {
			delayDir = oh.DataDirectory[13]
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 13 {
			delayDir = oh.DataDirectory[13]
		}
	}

	if delayDir.VirtualAddress == 0 || delayDir.Size == 0 {
		return
	}

	// Find section containing delay import directory
	var sec *pe.Section
	for _, s := range f.Sections {
		if delayDir.VirtualAddress >= s.VirtualAddress &&
			delayDir.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			sec = s
			break
		}
	}
	if sec == nil {
		return
	}

	secData, err := sec.Data()
	if err != nil {
		return
	}

	dirOff := delayDir.VirtualAddress - sec.VirtualAddress

	// Each ImgDelayDescr is 32 bytes, terminated by all-zero entry
	var dlls []string
	for i := 0; i < 100; i++ { // safety limit
		off := int(dirOff) + i*32
		if off+32 > len(secData) {
			break
		}

		// grAttrs at offset 0, rvaDLLName at offset 4
		attrs := binary.LittleEndian.Uint32(secData[off:])
		dllNameRVA := binary.LittleEndian.Uint32(secData[off+4:])

		// All-zero entry terminates the list
		if attrs == 0 && dllNameRVA == 0 {
			break
		}

		// Read DLL name (RVA to string)
		dllName := readPEString(f, dllNameRVA)
		if dllName == "" {
			dllName = fmt.Sprintf("(RVA: 0x%x)", dllNameRVA)
		}
		dlls = append(dlls, dllName)
	}

	if len(dlls) == 0 {
		return
	}
	sb.WriteString(fmt.Sprintf("\nDelay Imports (%d DLLs):\n", len(dlls)))
	for _, dll := range dlls {
		sb.WriteString(fmt.Sprintf("  %s\n", dll))
	}
}

// readPEString reads a null-terminated ASCII string at the given RVA.
func readPEString(f *pe.File, rva uint32) string {
	if rva == 0 {
		return ""
	}
	for _, s := range f.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
			secData, err := s.Data()
			if err != nil {
				return ""
			}
			off := rva - s.VirtualAddress
			if int(off) >= len(secData) {
				return ""
			}
			end := int(off)
			for end < len(secData) && secData[end] != 0 && end-int(off) < 260 {
				end++
			}
			return string(secData[off:end])
		}
	}
	return ""
}

// parseLoadConfig extracts IMAGE_LOAD_CONFIG_DIRECTORY (DataDirectory[10]).
// Shows security cookie, SafeSEH handler count, and Control Flow Guard status.
func parseLoadConfig(f *pe.File, sb *strings.Builder) {
	var loadCfgDir pe.DataDirectory
	var is64 bool
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 10 {
			loadCfgDir = oh.DataDirectory[10]
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 10 {
			loadCfgDir = oh.DataDirectory[10]
		}
		is64 = true
	}

	if loadCfgDir.VirtualAddress == 0 || loadCfgDir.Size == 0 {
		return
	}

	// Find section containing load config
	var sec *pe.Section
	for _, s := range f.Sections {
		if loadCfgDir.VirtualAddress >= s.VirtualAddress &&
			loadCfgDir.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			sec = s
			break
		}
	}
	if sec == nil {
		return
	}

	secData, err := sec.Data()
	if err != nil {
		return
	}

	off := int(loadCfgDir.VirtualAddress - sec.VirtualAddress)

	// First DWORD is the struct size — tells us which version of the structure we have
	if off+4 > len(secData) {
		return
	}
	structSize := binary.LittleEndian.Uint32(secData[off:])

	sb.WriteString(fmt.Sprintf("\nLoad Config (size: %d bytes):\n", structSize))

	if is64 {
		parseLoadConfig64(secData, off, structSize, sb)
	} else {
		parseLoadConfig32(secData, off, structSize, sb)
	}
}

func parseLoadConfig64(data []byte, off int, size uint32, sb *strings.Builder) {
	// IMAGE_LOAD_CONFIG_DIRECTORY64 key offsets:
	// 0x58: SecurityCookie (8 bytes)
	// 0x60: SEHandlerTable (8 bytes)
	// 0x68: SEHandlerCount (8 bytes)
	// 0x70: GuardCFCheckFunctionPointer (8 bytes)
	// 0x80: GuardCFFunctionTable (8 bytes)
	// 0x88: GuardCFFunctionCount (8 bytes)
	// 0x90: GuardFlags (4 bytes)

	if size >= 0x60 && off+0x60 <= len(data) {
		cookie := binary.LittleEndian.Uint64(data[off+0x58:])
		if cookie != 0 {
			sb.WriteString(fmt.Sprintf("  Security Cookie: 0x%x\n", cookie))
		}
	}

	if size >= 0x70 && off+0x70 <= len(data) {
		seCount := binary.LittleEndian.Uint64(data[off+0x68:])
		if seCount > 0 {
			sb.WriteString(fmt.Sprintf("  SafeSEH Handlers: %d\n", seCount))
		}
	}

	if size >= 0x94 && off+0x94 <= len(data) {
		cfgTable := binary.LittleEndian.Uint64(data[off+0x80:])
		cfgCount := binary.LittleEndian.Uint64(data[off+0x88:])
		guardFlags := binary.LittleEndian.Uint32(data[off+0x90:])

		if cfgCount > 0 || cfgTable != 0 {
			sb.WriteString(fmt.Sprintf("  CFG Function Table: 0x%x (%d functions)\n", cfgTable, cfgCount))
			sb.WriteString(fmt.Sprintf("  Guard Flags: 0x%x", guardFlags))
			if flags := decodeGuardFlags(guardFlags); flags != "" {
				sb.WriteString(fmt.Sprintf(" [%s]", flags))
			}
			sb.WriteString("\n")
		}
	}
}

func parseLoadConfig32(data []byte, off int, size uint32, sb *strings.Builder) {
	// IMAGE_LOAD_CONFIG_DIRECTORY32 key offsets:
	// 0x3C: SecurityCookie (4 bytes)
	// 0x40: SEHandlerTable (4 bytes)
	// 0x44: SEHandlerCount (4 bytes)
	// 0x48: GuardCFCheckFunctionPointer (4 bytes)
	// 0x50: GuardCFFunctionTable (4 bytes)
	// 0x54: GuardCFFunctionCount (4 bytes)
	// 0x58: GuardFlags (4 bytes)

	if size >= 0x40 && off+0x40 <= len(data) {
		cookie := binary.LittleEndian.Uint32(data[off+0x3C:])
		if cookie != 0 {
			sb.WriteString(fmt.Sprintf("  Security Cookie: 0x%x\n", cookie))
		}
	}

	if size >= 0x48 && off+0x48 <= len(data) {
		seCount := binary.LittleEndian.Uint32(data[off+0x44:])
		if seCount > 0 {
			sb.WriteString(fmt.Sprintf("  SafeSEH Handlers: %d\n", seCount))
		}
	}

	if size >= 0x5C && off+0x5C <= len(data) {
		cfgTable := binary.LittleEndian.Uint32(data[off+0x50:])
		cfgCount := binary.LittleEndian.Uint32(data[off+0x54:])
		guardFlags := binary.LittleEndian.Uint32(data[off+0x58:])

		if cfgCount > 0 || cfgTable != 0 {
			sb.WriteString(fmt.Sprintf("  CFG Function Table: 0x%x (%d functions)\n", cfgTable, cfgCount))
			sb.WriteString(fmt.Sprintf("  Guard Flags: 0x%x", guardFlags))
			if flags := decodeGuardFlags(guardFlags); flags != "" {
				sb.WriteString(fmt.Sprintf(" [%s]", flags))
			}
			sb.WriteString("\n")
		}
	}
}

func decodeGuardFlags(flags uint32) string {
	type gflag struct {
		mask uint32
		name string
	}
	checks := []gflag{
		{0x00000100, "CF_INSTRUMENTED"},
		{0x00000200, "CFW_INSTRUMENTED"},
		{0x00000400, "CF_FUNCTION_TABLE_PRESENT"},
		{0x00000800, "SECURITY_COOKIE_UNUSED"},
		{0x00001000, "PROTECT_DELAYLOAD_IAT"},
		{0x00002000, "DELAYLOAD_IAT_IN_ITS_OWN_SECTION"},
		{0x00004000, "CF_EXPORT_SUPPRESSION_INFO_PRESENT"},
		{0x00008000, "CF_ENABLE_EXPORT_SUPPRESSION"},
		{0x00010000, "CF_LONGJUMP_TABLE_PRESENT"},
		{0x00020000, "RF_INSTRUMENTED"},
		{0x00040000, "RF_ENABLE"},
		{0x00080000, "RF_STRICT"},
	}
	var parts []string
	for _, g := range checks {
		if flags&g.mask != 0 {
			parts = append(parts, g.name)
		}
	}
	return strings.Join(parts, ", ")
}

// parseHexAddr parses a hex string (with or without 0x prefix) to uint64.
func parseHexAddr(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return 0, fmt.Errorf("empty address")
	}
	return strconv.ParseUint(s, 16, 64)
}

// fileOffsetToRVA converts a file offset to an RVA using section headers.
// Returns 0 and false if the offset is not within any section.
func fileOffsetToRVA(f *pe.File, fileOff uint32) (uint32, bool) {
	for _, s := range f.Sections {
		secStart := s.Offset
		secEnd := s.Offset + s.Size
		if fileOff >= secStart && fileOff < secEnd {
			return s.VirtualAddress + (fileOff - secStart), true
		}
	}
	return 0, false
}

// parseImportsWithIAT parses the Import Directory to show per-function IAT slot VAs.
// IAT VAs are what FF 15/25 [rip+disp32] instructions reference, making them
// essential for xref cross-referencing.
func parseImportsWithIAT(f *pe.File, imageBase uint64, sb *strings.Builder) {
	var importDir pe.DataDirectory
	var is64 bool
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 1 {
			importDir = oh.DataDirectory[1]
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 1 {
			importDir = oh.DataDirectory[1]
		}
		is64 = true
	}

	if importDir.VirtualAddress == 0 || importDir.Size == 0 {
		// Fallback to Go's ImportedSymbols (no IAT info)
		imports, err := f.ImportedSymbols()
		if err == nil && len(imports) > 0 {
			sb.WriteString(fmt.Sprintf("\nImports (%d functions, no IAT info):\n", len(imports)))
			for _, sym := range imports {
				sb.WriteString(fmt.Sprintf("  %s\n", sym))
			}
		}
		return
	}

	// Find section containing import directory
	var sec *pe.Section
	for _, s := range f.Sections {
		if importDir.VirtualAddress >= s.VirtualAddress &&
			importDir.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			sec = s
			break
		}
	}
	if sec == nil {
		return
	}

	secData, err := sec.Data()
	if err != nil {
		return
	}

	dirOff := importDir.VirtualAddress - sec.VirtualAddress

	// Parse IMAGE_IMPORT_DESCRIPTOR entries (20 bytes each, null-terminated)
	type importDLL struct {
		name       string
		iatRVA     uint32 // FirstThunk RVA (IAT base for this DLL)
		thunkRVA   uint32 // OriginalFirstThunk RVA (for name lookup)
	}

	var dlls []importDLL
	totalFuncs := 0
	for i := 0; i < 500; i++ { // safety limit
		off := int(dirOff) + i*20
		if off+20 > len(secData) {
			break
		}

		origThunk := binary.LittleEndian.Uint32(secData[off:])
		nameRVA := binary.LittleEndian.Uint32(secData[off+12:])
		firstThunk := binary.LittleEndian.Uint32(secData[off+16:])

		// All-zero entry terminates
		if origThunk == 0 && nameRVA == 0 && firstThunk == 0 {
			break
		}

		dllName := readPEString(f, nameRVA)
		if dllName == "" {
			dllName = fmt.Sprintf("(RVA: 0x%x)", nameRVA)
		}

		// Prefer OriginalFirstThunk for name lookup (FirstThunk may be overwritten at load time)
		lookupThunk := origThunk
		if lookupThunk == 0 {
			lookupThunk = firstThunk
		}

		dlls = append(dlls, importDLL{name: dllName, iatRVA: firstThunk, thunkRVA: lookupThunk})
	}

	ptrSize := uint32(4)
	if is64 {
		ptrSize = 8
	}

	sb.WriteString(fmt.Sprintf("\nImports (%d DLLs):\n", len(dlls)))

	for _, dll := range dlls {
		// Read thunk array to resolve function names
		var thunkData []byte
		for _, s := range f.Sections {
			if dll.thunkRVA >= s.VirtualAddress &&
				dll.thunkRVA < s.VirtualAddress+s.VirtualSize {
				sd, err := s.Data()
				if err != nil {
					break
				}
				off := dll.thunkRVA - s.VirtualAddress
				thunkData = sd[off:]
				break
			}
		}

		// Parse each thunk entry to get function name + IAT slot VA
		type iatEntry struct {
			va   uint64
			name string
		}
		var entries []iatEntry
		iatSlotRVA := dll.iatRVA
		for j := 0; len(thunkData) >= int(ptrSize) && j < 2000; j++ {
			var thunkVal uint64
			if is64 {
				thunkVal = binary.LittleEndian.Uint64(thunkData[:8])
			} else {
				thunkVal = uint64(binary.LittleEndian.Uint32(thunkData[:4]))
			}
			if thunkVal == 0 {
				break
			}

			var funcName string
			ordinalFlag := uint64(1) << 63
			if !is64 {
				ordinalFlag = uint64(1) << 31
			}
			if thunkVal&ordinalFlag != 0 {
				funcName = fmt.Sprintf("Ordinal_%d", thunkVal&0xFFFF)
			} else {
				// IMAGE_IMPORT_BY_NAME: 2-byte hint + name string
				nameRVA := uint32(thunkVal)
				if nameStr := readPEString(f, nameRVA+2); nameStr != "" {
					funcName = nameStr
				} else {
					funcName = fmt.Sprintf("(RVA: 0x%x)", nameRVA)
				}
			}

			entries = append(entries, iatEntry{
				va:   imageBase + uint64(iatSlotRVA),
				name: funcName,
			})
			thunkData = thunkData[ptrSize:]
			iatSlotRVA += ptrSize
			totalFuncs++
		}

		sb.WriteString(fmt.Sprintf("  %s (%d):\n", dll.name, len(entries)))
		for _, e := range entries {
			sb.WriteString(fmt.Sprintf("    0x%x  %s\n", e.va, e.name))
		}
	}
}

// peSymbolMap builds a map of VA -> symbol name from imports (IAT slots) and exports.
// Used by disassembler for inline annotations (e.g. "call [rip+0x1234] ; CreateFileW").
func peSymbolMap(f *pe.File, imageBase uint64) map[uint64]string {
	syms := make(map[uint64]string)

	is64 := false
	if _, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		is64 = true
	}

	ptrSize := uint32(4)
	if is64 {
		ptrSize = 8
	}

	// Imports: map IAT slot VA -> function name
	var importDir pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 1 {
			importDir = oh.DataDirectory[1]
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 1 {
			importDir = oh.DataDirectory[1]
		}
	}
	if importDir.VirtualAddress != 0 && importDir.Size != 0 {
		var sec *pe.Section
		for _, s := range f.Sections {
			if importDir.VirtualAddress >= s.VirtualAddress &&
				importDir.VirtualAddress < s.VirtualAddress+s.VirtualSize {
				sec = s
				break
			}
		}
		if sec != nil {
			if secData, err := sec.Data(); err == nil {
				dirOff := importDir.VirtualAddress - sec.VirtualAddress
				for i := 0; i < 500; i++ {
					off := int(dirOff) + i*20
					if off+20 > len(secData) {
						break
					}
					origThunk := binary.LittleEndian.Uint32(secData[off:])
					nameRVA := binary.LittleEndian.Uint32(secData[off+12:])
					firstThunk := binary.LittleEndian.Uint32(secData[off+16:])
					if origThunk == 0 && nameRVA == 0 && firstThunk == 0 {
						break
					}
					lookupThunk := origThunk
					if lookupThunk == 0 {
						lookupThunk = firstThunk
					}
					// Read thunk array
					var thunkData []byte
					for _, s := range f.Sections {
						if lookupThunk >= s.VirtualAddress &&
							lookupThunk < s.VirtualAddress+s.VirtualSize {
							if sd, err := s.Data(); err == nil {
								thunkData = sd[lookupThunk-s.VirtualAddress:]
							}
							break
						}
					}
					iatRVA := firstThunk
					for j := 0; len(thunkData) >= int(ptrSize) && j < 2000; j++ {
						var tv uint64
						if is64 {
							tv = binary.LittleEndian.Uint64(thunkData[:8])
						} else {
							tv = uint64(binary.LittleEndian.Uint32(thunkData[:4]))
						}
						if tv == 0 {
							break
						}
						ordFlag := uint64(1) << 63
						if !is64 {
							ordFlag = uint64(1) << 31
						}
						var name string
						if tv&ordFlag != 0 {
							name = fmt.Sprintf("Ordinal_%d", tv&0xFFFF)
						} else {
							name = readPEString(f, uint32(tv)+2)
						}
						if name != "" {
							syms[imageBase+uint64(iatRVA)] = name
						}
						thunkData = thunkData[ptrSize:]
						iatRVA += ptrSize
					}
				}
			}
		}
	}

	// Exports: map function VA -> name
	exports := parseExports(f)
	for _, exp := range exports {
		va := imageBase + uint64(exp.rva)
		syms[va] = exp.name
	}

	return syms
}

// vaResolved holds the result of resolving a VA parameter to a file offset.
// Shared by disassemble, hexdump, and any offset-based operation that accepts VA input.
// Operations with complex VA handling (e.g. function_at with .pdata traversal and
// neighbor suggestions) do their own parsing instead.
type vaResolved struct {
	FileOffset  int64    // file offset corresponding to the VA
	DisplayBase uint64   // for address display: addr = displayBase + fileOffset + pos
	RVA         uint32   // RVA = VA - ImageBase
	ImageBase   uint64   // PE ImageBase
	PEFile      *pe.File // caller must defer Close()
}

// resolveVA converts a VA string to a file offset using PE headers.
// Returns a vaResolved with the PE file kept open (caller must close PEFile).
// Validates: hex parse, PE format, imageBase bounds, RVA 4GB limit, section mapping.
func resolveVA(filePath, vaStr string) (*vaResolved, error) {
	va, err := parseHexAddr(vaStr)
	if err != nil {
		return nil, fmt.Errorf("invalid va: %s", vaStr)
	}

	f, err := pe.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("va parameter requires a PE file: %w", err)
	}

	imageBase := peImageBase(f)
	if va < imageBase {
		f.Close()
		return nil, fmt.Errorf("va 0x%x is below image base 0x%x", va, imageBase)
	}
	if va-imageBase > 0xFFFFFFFF {
		f.Close()
		return nil, fmt.Errorf("va 0x%x is too far from image base 0x%x (RVA exceeds 4GB)", va, imageBase)
	}

	rva := uint32(va - imageBase)
	fileOff, _, err := rvaToFileOffset(f, rva)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("va 0x%x: %w. Try using offset parameter instead", va, err)
	}

	// displayBase: maps file offset 0 to the correct VA range
	// so that displayBase + fileOffset = VA
	displayBase := va - uint64(fileOff)

	return &vaResolved{
		FileOffset:  int64(fileOff),
		DisplayBase: displayBase,
		RVA:         rva,
		ImageBase:   imageBase,
		PEFile:      f,
	}, nil
}

// peImageBase extracts ImageBase from PE OptionalHeader (32 or 64-bit).
func peImageBase(f *pe.File) uint64 {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		return oh.ImageBase
	}
	return 0
}
