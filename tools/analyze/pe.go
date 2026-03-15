package analyze

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
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
	sb.WriteString(fmt.Sprintf("Characteristics: 0x%x\n", f.FileHeader.Characteristics))

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
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
		sb.WriteString(fmt.Sprintf("Image Base: 0x%x\n", oh.ImageBase))
		sb.WriteString(fmt.Sprintf("Entry Point RVA: 0x%x\n", oh.AddressOfEntryPoint))
		sb.WriteString(fmt.Sprintf("Section Alignment: 0x%x\n", oh.SectionAlignment))
		sb.WriteString(fmt.Sprintf("File Alignment: 0x%x\n", oh.FileAlignment))
		sb.WriteString(fmt.Sprintf("Image Size: 0x%x\n", oh.SizeOfImage))
	}

	// Sections
	filterSection := strings.TrimSpace(input.Section)
	sb.WriteString(fmt.Sprintf("\nSections (%d):\n", len(f.Sections)))
	sb.WriteString(fmt.Sprintf("  %-10s %-12s %-12s %-12s %-12s %s\n",
		"Name", "VirtAddr", "VirtSize", "RawOffset", "RawSize", "Flags"))

	for _, s := range f.Sections {
		name := s.Name
		if filterSection != "" && !strings.EqualFold(name, filterSection) {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %-10s 0x%-10x 0x%-10x 0x%-10x 0x%-10x 0x%x\n",
			name, s.VirtualAddress, s.VirtualSize,
			s.Offset, s.Size, s.Characteristics))
	}

	// RVA to file offset conversion if requested
	if input.RVA != "" {
		rvaStr := strings.TrimPrefix(input.RVA, "0x")
		rvaStr = strings.TrimPrefix(rvaStr, "0X")
		rva, err := strconv.ParseUint(rvaStr, 16, 64)
		if err != nil {
			sb.WriteString(fmt.Sprintf("\nInvalid RVA value: %s (expected hex, e.g. '0x36A20')\n", input.RVA))
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

	// Imports
	imports, err := f.ImportedSymbols()
	if err == nil && len(imports) > 0 {
		// Group by DLL
		dllMap := make(map[string][]string)
		var dllOrder []string
		for _, sym := range imports {
			// Format: "DLLName:FunctionName"
			parts := strings.SplitN(sym, ":", 2)
			if len(parts) == 2 {
				dll := parts[0]
				fn := parts[1]
				if _, exists := dllMap[dll]; !exists {
					dllOrder = append(dllOrder, dll)
				}
				dllMap[dll] = append(dllMap[dll], fn)
			}
		}

		sb.WriteString(fmt.Sprintf("\nImports (%d DLLs, %d functions):\n", len(dllOrder), len(imports)))
		for _, dll := range dllOrder {
			fns := dllMap[dll]
			sb.WriteString(fmt.Sprintf("  %s (%d):", dll, len(fns)))
			// Show first few functions inline, rest as count
			if len(fns) <= 5 {
				sb.WriteString(" " + strings.Join(fns, ", "))
			} else {
				sb.WriteString(" " + strings.Join(fns[:5], ", "))
				sb.WriteString(fmt.Sprintf(" ... +%d more", len(fns)-5))
			}
			sb.WriteString("\n")
		}
	}

	// Exports (manually parse export directory for DLLs)
	exports := parseExports(f)
	if len(exports) > 0 {
		sb.WriteString(fmt.Sprintf("\nExports (%d):\n", len(exports)))
		for _, exp := range exports {
			sb.WriteString(fmt.Sprintf("  0x%x  %s\n", exp.rva, exp.name))
		}
	}

	return sb.String(), nil
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
