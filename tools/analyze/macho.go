package analyze

import (
	"debug/macho"
	"fmt"
	"strings"
)

// opMachOInfo parses Mach-O binaries (macOS/iOS) and displays
// header info, load commands, sections, and imported symbols.
func opMachOInfo(input AnalyzeInput) (string, error) {
	f, err := macho.Open(input.FilePath)
	if err != nil {
		// Try as fat (universal) binary
		return tryFatMachO(input)
	}
	defer f.Close()

	return formatMachO(f, input.Section)
}

func tryFatMachO(input AnalyzeInput) (string, error) {
	fat, err := macho.OpenFat(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("not a valid Mach-O file: %w", err)
	}
	defer fat.Close()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Universal (Fat) Binary — %d architectures:\n\n", len(fat.Arches)))

	for i, arch := range fat.Arches {
		sb.WriteString(fmt.Sprintf("=== Architecture %d: %s / 0x%x ===\n", i+1, arch.Cpu, arch.SubCpu))
		result, err := formatMachO(arch.File, input.Section)
		if err != nil {
			sb.WriteString(fmt.Sprintf("  Error: %v\n", err))
		} else {
			sb.WriteString(result)
		}
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

func formatMachO(f *macho.File, filterSection string) (string, error) {
	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("CPU: %s / 0x%x\n", f.Cpu, f.SubCpu))
	sb.WriteString(fmt.Sprintf("Type: %s\n", f.Type))
	sb.WriteString(fmt.Sprintf("Flags: 0x%x\n", uint32(f.Flags)))

	// Flag descriptions for common flags
	if f.Flags&macho.FlagPIE != 0 {
		sb.WriteString("  PIE (Position Independent Executable)\n")
	}
	if f.Flags&macho.FlagDyldLink != 0 {
		sb.WriteString("  DYLDLINK\n")
	}
	if f.Flags&macho.FlagNoUndefs != 0 {
		sb.WriteString("  NOUNDEFS\n")
	}

	// Load commands
	sb.WriteString(fmt.Sprintf("\nLoad Commands (%d):\n", len(f.Loads)))
	for _, load := range f.Loads {
		raw := load.Raw()
		if len(raw) >= 4 {
			// First 4 bytes = cmd type
			cmd := macho.LoadCmd(uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16 | uint32(raw[3])<<24)
			sb.WriteString(fmt.Sprintf("  %s\n", cmd))
		}
	}

	// Sections
	filter := strings.TrimSpace(filterSection)
	if len(f.Sections) > 0 {
		sb.WriteString(fmt.Sprintf("\nSections (%d):\n", len(f.Sections)))
		sb.WriteString(fmt.Sprintf("  %-20s %-16s %-12s %-12s %-12s %s\n",
			"Name", "Segment", "Addr", "Offset", "Size", "Flags"))

		for _, s := range f.Sections {
			name := s.Name
			if filter != "" && !strings.EqualFold(name, filter) {
				continue
			}

			flags := machoSectionFlags(s.Flags)
			sb.WriteString(fmt.Sprintf("  %-20s %-16s 0x%-10x 0x%-10x 0x%-10x %s\n",
				name, s.Seg, s.Addr, s.Offset, s.Size, flags))
		}
	}

	// Segments with permission analysis
	sb.WriteString("\nSegments:\n")
	sb.WriteString(fmt.Sprintf("  %-16s %-12s %-12s %-12s %-8s %-8s %s\n",
		"Name", "Addr", "Size", "FileSize", "MaxProt", "InitProt", ""))

	for _, load := range f.Loads {
		if seg, ok := load.(*macho.Segment); ok {
			maxProt := machoProtString(seg.Maxprot)
			initProt := machoProtString(seg.Prot)
			warn := ""
			// RWX warning: segment with both write and execute permission
			if seg.Prot&0x02 != 0 && seg.Prot&0x04 != 0 {
				warn = "⚠ W+X"
			}
			sb.WriteString(fmt.Sprintf("  %-16s 0x%-10x 0x%-10x 0x%-10x %-8s %-8s %s\n",
				seg.Name, seg.Addr, seg.Memsz, seg.Filesz, maxProt, initProt, warn))
		}
	}

	// Imported libraries
	libs, err := f.ImportedLibraries()
	if err == nil && len(libs) > 0 {
		sb.WriteString(fmt.Sprintf("\nImported Libraries (%d):\n", len(libs)))
		for _, lib := range libs {
			sb.WriteString(fmt.Sprintf("  %s\n", lib))
		}
	}

	// Imported symbols
	syms, err := f.ImportedSymbols()
	if err == nil && len(syms) > 0 {
		sb.WriteString(fmt.Sprintf("\nImported Symbols (%d):\n", len(syms)))
		shown := 0
		for _, sym := range syms {
			sb.WriteString(fmt.Sprintf("  %s\n", sym))
			shown++
			if shown >= 200 {
				sb.WriteString(fmt.Sprintf("  ... +%d more\n", len(syms)-shown))
				break
			}
		}
	}

	return sb.String(), nil
}

// machoProtString converts Mach-O protection flags to a human-readable string.
// Mach-O uses: 0x01=R, 0x02=W, 0x04=X
func machoProtString(prot uint32) string {
	var parts []string
	if prot&0x01 != 0 {
		parts = append(parts, "R")
	}
	if prot&0x02 != 0 {
		parts = append(parts, "W")
	}
	if prot&0x04 != 0 {
		parts = append(parts, "X")
	}
	if len(parts) == 0 {
		return "---"
	}
	return strings.Join(parts, "")
}

func machoSectionFlags(flags uint32) string {
	// Mach-O section type is in low 8 bits
	stype := flags & 0xFF
	typeNames := map[uint32]string{
		0x0: "REGULAR",
		0x1: "ZEROFILL",
		0x2: "CSTRING_LITERALS",
		0x3: "4BYTE_LITERALS",
		0x4: "8BYTE_LITERALS",
		0x5: "LITERAL_POINTERS",
		0x6: "NON_LAZY_SYMBOL_POINTERS",
		0x7: "LAZY_SYMBOL_POINTERS",
		0x8: "SYMBOL_STUBS",
	}
	if name, ok := typeNames[stype]; ok {
		return name
	}
	return fmt.Sprintf("0x%x", flags)
}
