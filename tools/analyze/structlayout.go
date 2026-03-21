package analyze

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	defaultStructLength = 64
	maxStructLength     = 512
)

// opStructLayout dumps a memory region as a structured layout, interpreting
// each pointer-sized slot with symbol/section annotation.
// Useful for inspecting vtables, object layouts, and data structures.
func opStructLayout(input AnalyzeInput) (string, error) {
	vaStr := input.VA
	if vaStr == "" {
		return "", fmt.Errorf("va is required for struct_layout (starting virtual address)")
	}

	startVA, err := parseHexAddr(vaStr)
	if err != nil {
		return "", fmt.Errorf("invalid va: %s", vaStr)
	}

	length := input.Length
	if length <= 0 {
		length = defaultStructLength
	}
	if length > maxStructLength {
		length = maxStructLength
	}

	f, err := pe.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("struct_layout requires a PE file: %w", err)
	}
	defer f.Close()

	imageBase := peImageBase(f)
	is64 := f.FileHeader.Machine == 0x8664 || f.FileHeader.Machine == 0xaa64
	ptrSize := 4
	if is64 {
		ptrSize = 8
	}

	symbols := peSymbolMap(f, imageBase)

	// Read the data block
	data, err := readPEBytesAtVA(f, imageBase, startVA, length)
	if err != nil {
		return "", fmt.Errorf("cannot read data at 0x%x: %w", startVA, err)
	}

	var sb strings.Builder
	secName := ""
	if startVA >= imageBase && startVA-imageBase <= 0xFFFFFFFF {
		rva := uint32(startVA - imageBase)
		secName = sectionNameForRVA(f, rva)
	}
	if secName != "" {
		sb.WriteString(fmt.Sprintf("Struct layout at 0x%x [%s] (%d-bit, %d bytes):\n\n",
			startVA, secName, ptrSize*8, len(data)))
	} else {
		sb.WriteString(fmt.Sprintf("Struct layout at 0x%x (%d-bit, %d bytes):\n\n",
			startVA, ptrSize*8, len(data)))
	}

	sb.WriteString(fmt.Sprintf("%-8s %-18s %-18s %s\n", "Offset", "Hex", "Value", "Annotation"))
	sb.WriteString(strings.Repeat("-", 70) + "\n")

	numSlots := len(data) / ptrSize
	for i := 0; i < numSlots; i++ {
		off := i * ptrSize
		slotVA := startVA + uint64(off)

		var val uint64
		var hexStr string
		if ptrSize == 8 {
			val = binary.LittleEndian.Uint64(data[off : off+8])
			hexStr = fmt.Sprintf("%02x %02x %02x %02x %02x %02x %02x %02x",
				data[off], data[off+1], data[off+2], data[off+3],
				data[off+4], data[off+5], data[off+6], data[off+7])
		} else {
			val = uint64(binary.LittleEndian.Uint32(data[off : off+4]))
			hexStr = fmt.Sprintf("%02x %02x %02x %02x",
				data[off], data[off+1], data[off+2], data[off+3])
		}

		ann := classifyValue(f, imageBase, val, symbols)
		sb.WriteString(fmt.Sprintf("+0x%-5x %-18s 0x%-16x %s\n",
			off, hexStr, val, ann))

		// Also show for slot VA if it has a symbol
		if name, ok := symbols[slotVA]; ok {
			sb.WriteString(fmt.Sprintf("         ^ %s\n", name))
		}
	}

	// Show remaining bytes if not aligned to pointer size
	remaining := len(data) % ptrSize
	if remaining > 0 {
		off := numSlots * ptrSize
		var parts []string
		for j := 0; j < remaining; j++ {
			parts = append(parts, fmt.Sprintf("%02x", data[off+j]))
		}
		sb.WriteString(fmt.Sprintf("+0x%-5x %s  (trailing %d bytes)\n",
			off, strings.Join(parts, " "), remaining))
	}

	return sb.String(), nil
}

// classifyValue interprets a pointer-sized value: symbol, section classification, or null.
func classifyValue(f *pe.File, imageBase, val uint64, symbols map[uint64]string) string {
	if val == 0 {
		return "[null]"
	}

	// Check symbol map first
	if name, ok := symbols[val]; ok {
		return name
	}

	// Check if it points to a valid section
	if val >= imageBase && val-imageBase <= 0xFFFFFFFF {
		rva := uint32(val - imageBase)
		for _, s := range f.Sections {
			if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
				// Classify by section characteristics
				isExec := s.Characteristics&0x20000000 != 0
				isWrite := s.Characteristics&0x80000000 != 0
				if isExec {
					return fmt.Sprintf("[code] %s", s.Name)
				}
				if isWrite {
					return fmt.Sprintf("[data] %s", s.Name)
				}
				return fmt.Sprintf("[rdata] %s", s.Name)
			}
		}
	}

	// Not a valid section pointer -- could be a scalar value
	return ""
}
