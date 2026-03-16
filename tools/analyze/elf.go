package analyze

import (
	"debug/elf"
	"fmt"
	"strings"
)

// opELFInfo parses ELF (Executable and Linkable Format) binaries and displays
// header info, sections, program headers, symbols, and dynamic imports.
func opELFInfo(input AnalyzeInput) (string, error) {
	f, err := elf.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("not a valid ELF file: %w", err)
	}
	defer f.Close()

	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("Class: %s\n", f.Class))
	sb.WriteString(fmt.Sprintf("Data: %s\n", f.Data))
	sb.WriteString(fmt.Sprintf("OS/ABI: %s\n", f.OSABI))
	sb.WriteString(fmt.Sprintf("Type: %s\n", f.Type))
	sb.WriteString(fmt.Sprintf("Machine: %s\n", f.Machine))
	sb.WriteString(fmt.Sprintf("Entry Point: 0x%x\n", f.Entry))

	// Sections
	filterSection := strings.TrimSpace(input.Section)
	sb.WriteString(fmt.Sprintf("\nSections (%d):\n", len(f.Sections)))
	sb.WriteString(fmt.Sprintf("  %-20s %-8s %-12s %-12s %-12s %-12s %s\n",
		"Name", "Type", "Addr", "Offset", "Size", "EntSize", "Flags"))

	for _, s := range f.Sections {
		if filterSection != "" && !strings.EqualFold(s.Name, filterSection) {
			continue
		}
		flags := elfSectionFlags(s.Flags)
		sb.WriteString(fmt.Sprintf("  %-20s %-8s 0x%-10x 0x%-10x 0x%-10x 0x%-10x %s",
			s.Name, elfSectionTypeName(s.Type), s.Addr, s.Offset, s.Size, s.Entsize, flags))

		// RWX warning: sections that are both writable and executable are suspicious
		if s.Flags&elf.SHF_WRITE != 0 && s.Flags&elf.SHF_EXECINSTR != 0 {
			sb.WriteString("  ⚠ W+X")
		}
		sb.WriteString("\n")
	}

	// Program headers (segments)
	if len(f.Progs) > 0 {
		sb.WriteString(fmt.Sprintf("\nProgram Headers (%d):\n", len(f.Progs)))
		sb.WriteString(fmt.Sprintf("  %-12s %-12s %-12s %-12s %-12s %s\n",
			"Type", "Offset", "VAddr", "FileSize", "MemSize", "Flags"))

		for _, p := range f.Progs {
			flags := elfProgFlags(p.Flags)
			sb.WriteString(fmt.Sprintf("  %-12s 0x%-10x 0x%-10x 0x%-10x 0x%-10x %s",
				p.Type, p.Off, p.Vaddr, p.Filesz, p.Memsz, flags))

			// RWX segment warning
			if p.Flags&elf.PF_W != 0 && p.Flags&elf.PF_X != 0 {
				sb.WriteString("  ⚠ W+X")
			}
			sb.WriteString("\n")
		}
	}

	// Dynamic imports
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
			sb.WriteString(fmt.Sprintf("  %s (lib: %s, version: %s)\n", sym.Name, sym.Library, sym.Version))
			shown++
			if shown >= 200 {
				sb.WriteString(fmt.Sprintf("  ... +%d more\n", len(syms)-shown))
				break
			}
		}
	}

	// Dynamic symbols (exports)
	dynSyms, err := f.DynamicSymbols()
	if err == nil && len(dynSyms) > 0 {
		// Filter to only exported symbols (non-zero value, defined section)
		var exports []elf.Symbol
		for _, sym := range dynSyms {
			if sym.Value != 0 && sym.Section != elf.SHN_UNDEF {
				exports = append(exports, sym)
			}
		}
		if len(exports) > 0 {
			sb.WriteString(fmt.Sprintf("\nExported Symbols (%d):\n", len(exports)))
			shown := 0
			for _, sym := range exports {
				sb.WriteString(fmt.Sprintf("  0x%x  %s\n", sym.Value, sym.Name))
				shown++
				if shown >= 200 {
					sb.WriteString(fmt.Sprintf("  ... +%d more\n", len(exports)-shown))
					break
				}
			}
		}
	}

	return sb.String(), nil
}

func elfSectionTypeName(t elf.SectionType) string {
	names := map[elf.SectionType]string{
		elf.SHT_NULL:     "NULL",
		elf.SHT_PROGBITS: "PROGBITS",
		elf.SHT_SYMTAB:   "SYMTAB",
		elf.SHT_STRTAB:   "STRTAB",
		elf.SHT_RELA:     "RELA",
		elf.SHT_HASH:     "HASH",
		elf.SHT_DYNAMIC:  "DYNAMIC",
		elf.SHT_NOTE:     "NOTE",
		elf.SHT_NOBITS:   "NOBITS",
		elf.SHT_REL:      "REL",
		elf.SHT_DYNSYM:   "DYNSYM",
	}
	if n, ok := names[t]; ok {
		return n
	}
	return fmt.Sprintf("0x%x", uint32(t))
}

func elfSectionFlags(f elf.SectionFlag) string {
	var parts []string
	if f&elf.SHF_WRITE != 0 {
		parts = append(parts, "W")
	}
	if f&elf.SHF_ALLOC != 0 {
		parts = append(parts, "A")
	}
	if f&elf.SHF_EXECINSTR != 0 {
		parts = append(parts, "X")
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "")
}

func elfProgFlags(f elf.ProgFlag) string {
	var parts []string
	if f&elf.PF_R != 0 {
		parts = append(parts, "R")
	}
	if f&elf.PF_W != 0 {
		parts = append(parts, "W")
	}
	if f&elf.PF_X != 0 {
		parts = append(parts, "X")
	}
	return strings.Join(parts, "")
}
