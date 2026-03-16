package analyze

import (
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"strings"
)

// opDWARFInfo extracts DWARF debug information from binaries.
// Shows compilation units (source files), functions with addresses,
// and variable types. Useful for determining if a binary was stripped,
// identifying source language, and finding function boundaries.
func opDWARFInfo(input AnalyzeInput) (string, error) {
	d, format, err := loadDWARF(input.FilePath)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("DWARF Debug Info (format: %s):\n\n", format))

	reader := d.Reader()

	var compUnits int
	var functions int
	var variables int
	var types int

	// Collect compilation units and their children
	type funcInfo struct {
		name    string
		lowPC   uint64
		highPC  uint64
		file    string
		line    int64
	}
	var funcs []funcInfo
	var compUnitNames []string
	var currentCU string

	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}

		switch entry.Tag {
		case dwarf.TagCompileUnit:
			compUnits++
			if name, ok := getAttrString(entry, dwarf.AttrName); ok {
				currentCU = name
				compUnitNames = append(compUnitNames, name)
			}

		case dwarf.TagSubprogram:
			functions++
			fi := funcInfo{}
			if name, ok := getAttrString(entry, dwarf.AttrName); ok {
				fi.name = name
			}
			if v, ok := getAttrUint(entry, dwarf.AttrLowpc); ok {
				fi.lowPC = v
			}
			if v, ok := getAttrUint(entry, dwarf.AttrHighpc); ok {
				fi.highPC = v
			}
			fi.file = currentCU
			if v, ok := getAttrInt(entry, dwarf.AttrDeclLine); ok {
				fi.line = v
			}
			if fi.name != "" {
				funcs = append(funcs, fi)
			}

		case dwarf.TagVariable, dwarf.TagFormalParameter:
			variables++

		case dwarf.TagBaseType, dwarf.TagStructType, dwarf.TagTypedef,
			dwarf.TagPointerType, dwarf.TagArrayType, dwarf.TagEnumerationType:
			types++
		}

		// Limit total entries to prevent excessive memory usage
		if compUnits+functions+variables+types > 50000 {
			sb.WriteString("(truncated — too many DWARF entries)\n\n")
			break
		}
	}

	// Summary
	sb.WriteString(fmt.Sprintf("Compilation Units: %d\n", compUnits))
	sb.WriteString(fmt.Sprintf("Functions: %d\n", functions))
	sb.WriteString(fmt.Sprintf("Variables/Parameters: %d\n", variables))
	sb.WriteString(fmt.Sprintf("Types: %d\n\n", types))

	// Compilation units (first 30)
	if len(compUnitNames) > 0 {
		sb.WriteString("Source Files (Compilation Units):\n")
		shown := 0
		for _, name := range compUnitNames {
			sb.WriteString(fmt.Sprintf("  %s\n", name))
			shown++
			if shown >= 30 {
				sb.WriteString(fmt.Sprintf("  ... +%d more\n", len(compUnitNames)-shown))
				break
			}
		}
		sb.WriteString("\n")
	}

	// Functions with addresses (first 50)
	if len(funcs) > 0 {
		sb.WriteString("Functions:\n")
		sb.WriteString(fmt.Sprintf("  %-18s %-18s %s\n", "Low PC", "High PC", "Name"))
		shown := 0
		for _, f := range funcs {
			highStr := ""
			if f.highPC > 0 {
				// highPC can be absolute or relative to lowPC
				if f.highPC > f.lowPC {
					highStr = fmt.Sprintf("0x%x", f.highPC)
				} else {
					highStr = fmt.Sprintf("0x%x", f.lowPC+f.highPC)
				}
			}
			sb.WriteString(fmt.Sprintf("  0x%-16x %-18s %s\n", f.lowPC, highStr, f.name))
			shown++
			if shown >= 50 {
				sb.WriteString(fmt.Sprintf("  ... +%d more\n", len(funcs)-shown))
				break
			}
		}
	}

	if compUnits == 0 && functions == 0 {
		sb.WriteString("Binary appears to be stripped — no debug information found.\n")
	}

	return sb.String(), nil
}

// loadDWARF tries PE, ELF, then Mach-O to extract DWARF data.
// The returned *dwarf.Data is self-contained (section data copied into memory),
// so the underlying file handle is closed immediately after extraction.
func loadDWARF(path string) (*dwarf.Data, string, error) {
	// Try PE
	if f, err := pe.Open(path); err == nil {
		d, dErr := f.DWARF()
		f.Close()
		if dErr == nil {
			return d, "PE", nil
		}
	}
	// Try ELF
	if f, err := elf.Open(path); err == nil {
		d, dErr := f.DWARF()
		f.Close()
		if dErr == nil {
			return d, "ELF", nil
		}
	}
	// Try Mach-O
	if f, err := macho.Open(path); err == nil {
		d, dErr := f.DWARF()
		f.Close()
		if dErr == nil {
			return d, "Mach-O", nil
		}
	}
	return nil, "", fmt.Errorf("no DWARF debug info found (binary may be stripped, or not PE/ELF/Mach-O)")
}

func getAttrString(entry *dwarf.Entry, attr dwarf.Attr) (string, bool) {
	field := entry.AttrField(attr)
	if field == nil {
		return "", false
	}
	if s, ok := field.Val.(string); ok {
		return s, true
	}
	return "", false
}

func getAttrUint(entry *dwarf.Entry, attr dwarf.Attr) (uint64, bool) {
	field := entry.AttrField(attr)
	if field == nil {
		return 0, false
	}
	switch v := field.Val.(type) {
	case uint64:
		return v, true
	case int64:
		return uint64(v), true
	}
	return 0, false
}

func getAttrInt(entry *dwarf.Entry, attr dwarf.Attr) (int64, bool) {
	field := entry.AttrField(attr)
	if field == nil {
		return 0, false
	}
	if v, ok := field.Val.(int64); ok {
		return v, true
	}
	return 0, false
}
