package analyze

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Standard PE resource type IDs
var resourceTypeNames = map[uint32]string{
	1:  "RT_CURSOR",
	2:  "RT_BITMAP",
	3:  "RT_ICON",
	4:  "RT_MENU",
	5:  "RT_DIALOG",
	6:  "RT_STRING",
	7:  "RT_FONTDIR",
	8:  "RT_FONT",
	9:  "RT_ACCELERATOR",
	10: "RT_RCDATA",
	11: "RT_MESSAGETABLE",
	12: "RT_GROUP_CURSOR",
	14: "RT_GROUP_ICON",
	16: "RT_VERSION",
	17: "RT_DLGINCLUDE",
	19: "RT_PLUGPLAY",
	20: "RT_VXD",
	21: "RT_ANICURSOR",
	22: "RT_ANIICON",
	23: "RT_HTML",
	24: "RT_MANIFEST",
}

// opResourceInfo parses PE resource directory and extracts resource metadata.
// Focuses on RT_VERSION (product name, company, version strings).
func opResourceInfo(input AnalyzeInput) (string, error) {
	f, err := pe.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("not a valid PE file: %w", err)
	}
	defer f.Close()

	// Find resource data directory (index 2)
	var resDir pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 2 {
			resDir = oh.DataDirectory[2]
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 2 {
			resDir = oh.DataDirectory[2]
		}
	}

	if resDir.VirtualAddress == 0 || resDir.Size == 0 {
		return "No resource directory found in this PE file.", nil
	}

	// Find section containing resources
	var resSec *pe.Section
	for _, s := range f.Sections {
		if resDir.VirtualAddress >= s.VirtualAddress &&
			resDir.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			resSec = s
			break
		}
	}
	if resSec == nil {
		return "Resource directory points to non-existent section.", nil
	}

	secData, err := resSec.Data()
	if err != nil {
		return "", fmt.Errorf("cannot read resource section: %w", err)
	}

	dirOff := resDir.VirtualAddress - resSec.VirtualAddress

	var sb strings.Builder
	sb.WriteString("PE Resource Directory:\n\n")

	// Parse root directory
	totalCount := 0
	entries, err := parseResourceDir(secData, dirOff, 0, &totalCount)
	if err != nil {
		return "", fmt.Errorf("cannot parse resource directory: %w", err)
	}

	// Summarize by type
	typeCounts := make(map[string]int)
	for _, e := range entries {
		typeCounts[e.typeName]++
	}

	sb.WriteString("Resource Types:\n")
	for typeName, count := range typeCounts {
		sb.WriteString(fmt.Sprintf("  %-20s %d entries\n", typeName, count))
	}

	sb.WriteString(fmt.Sprintf("\nTotal Resources: %d\n", len(entries)))

	// Show detailed entries (limit to 100)
	sb.WriteString("\nEntries:\n")
	sb.WriteString(fmt.Sprintf("  %-20s %-10s %-10s %-10s\n", "Type", "ID/Name", "Lang", "Size"))
	shown := 0
	for _, e := range entries {
		sb.WriteString(fmt.Sprintf("  %-20s %-10s %-10s %-10d\n",
			e.typeName, e.name, e.lang, e.size))
		shown++
		if shown >= 100 {
			sb.WriteString(fmt.Sprintf("  ... +%d more\n", len(entries)-shown))
			break
		}
	}

	// Try to extract VS_VERSION_INFO
	versionInfo := extractVersionInfo(secData, dirOff, resSec.VirtualAddress)
	if versionInfo != "" {
		sb.WriteString("\nVersion Info:\n")
		sb.WriteString(versionInfo)
	}

	return sb.String(), nil
}

type resourceEntry struct {
	typeName string
	name     string
	lang     string
	size     uint32
}

// parseResourceDir walks the 3-level PE resource directory tree.
// Level 0 = type, level 1 = name/ID, level 2 = language.
// totalCount tracks cumulative entries across all recursion levels to prevent
// OOM from malicious PEs with deeply nested resource directories.
func parseResourceDir(data []byte, offset uint32, depth int, totalCount *int) ([]resourceEntry, error) {
	const maxTotalEntries = 10000 // cumulative limit across all recursion levels

	if depth > 3 || int(offset)+16 > len(data) {
		return nil, nil
	}

	// IMAGE_RESOURCE_DIRECTORY: 16 bytes header
	// Guard uint32 overflow: offset + 16 could wrap on 32-bit
	if offset > uint32(len(data))-16 {
		return nil, nil
	}
	numNamed := binary.LittleEndian.Uint16(data[offset+12:])
	numID := binary.LittleEndian.Uint16(data[offset+14:])
	total := int(numNamed) + int(numID)

	// Per-directory sanity limit
	if total > 1000 {
		return nil, fmt.Errorf("too many resource entries: %d", total)
	}

	var entries []resourceEntry
	entryBase := int(offset) + 16 // use int to avoid uint32 overflow

	for i := 0; i < total; i++ {
		if *totalCount >= maxTotalEntries {
			return entries, fmt.Errorf("resource entry limit reached (%d)", maxTotalEntries)
		}

		entryOff := entryBase + i*8
		if entryOff+8 > len(data) {
			break
		}

		nameOrID := binary.LittleEndian.Uint32(data[entryOff:])
		dataOrSubdir := binary.LittleEndian.Uint32(data[entryOff+4:])

		isSubdir := dataOrSubdir&0x80000000 != 0
		subdirOff := dataOrSubdir & 0x7FFFFFFF

		entryName := ""
		if nameOrID&0x80000000 != 0 {
			// Named entry
			nameOff := nameOrID & 0x7FFFFFFF
			entryName = readResourceString(data, nameOff)
		} else {
			if depth == 0 {
				if name, ok := resourceTypeNames[nameOrID]; ok {
					entryName = name
				} else {
					entryName = fmt.Sprintf("Type_%d", nameOrID)
				}
			} else {
				entryName = fmt.Sprintf("%d", nameOrID)
			}
		}

		*totalCount++

		if isSubdir {
			subEntries, _ := parseResourceDir(data, subdirOff, depth+1, totalCount)
			for j := range subEntries {
				switch depth {
				case 0:
					subEntries[j].typeName = entryName
				case 1:
					subEntries[j].name = entryName
				case 2:
					subEntries[j].lang = entryName
				}
			}
			entries = append(entries, subEntries...)
		} else {
			// Data entry: IMAGE_RESOURCE_DATA_ENTRY (16 bytes)
			if int(subdirOff)+16 > len(data) {
				continue
			}
			dataSize := binary.LittleEndian.Uint32(data[subdirOff+4:])
			e := resourceEntry{size: dataSize}
			switch depth {
			case 0:
				e.typeName = entryName
			case 1:
				e.name = entryName
			case 2:
				e.lang = entryName
			}
			entries = append(entries, e)
		}
	}

	return entries, nil
}

func readResourceString(data []byte, offset uint32) string {
	if int(offset)+2 > len(data) {
		return "?"
	}
	length := binary.LittleEndian.Uint16(data[offset:])
	if length > 256 {
		length = 256
	}
	start := offset + 2
	if int(start)+int(length)*2 > len(data) {
		return "?"
	}
	// UTF-16LE string
	u16 := make([]uint16, length)
	for i := uint16(0); i < length; i++ {
		u16[i] = binary.LittleEndian.Uint16(data[start+uint32(i)*2:])
	}
	return string(utf16.Decode(u16))
}

// extractVersionInfo searches for VS_VERSION_INFO and parses StringFileInfo.
func extractVersionInfo(data []byte, dirOff, secVA uint32) string {
	// Look for the UTF-16LE signature "VS_VERSION_INFO"
	sig := encodeUTF16LE("VS_VERSION_INFO")
	idx := -1
	for i := 0; i < len(data)-len(sig); i++ {
		match := true
		for j := range sig {
			if data[i+j] != sig[j] {
				match = false
				break
			}
		}
		if match {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ""
	}

	// Search for StringFileInfo entries after VS_VERSION_INFO
	// Look for common version string keys
	keys := []string{
		"CompanyName", "FileDescription", "FileVersion",
		"InternalName", "LegalCopyright", "OriginalFilename",
		"ProductName", "ProductVersion",
	}

	var sb strings.Builder
	for _, key := range keys {
		value := findVersionString(data[idx:], key)
		if value != "" {
			sb.WriteString(fmt.Sprintf("  %-20s: %s\n", key, value))
		}
	}
	return sb.String()
}

func findVersionString(data []byte, key string) string {
	keyU16 := encodeUTF16LE(key)
	for i := 0; i < len(data)-len(keyU16)-4; i++ {
		match := true
		for j := range keyU16 {
			if data[i+j] != keyU16[j] {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		// Found key, value follows after padding
		valStart := i + len(keyU16)
		// Skip null terminators and align to DWORD
		for valStart < len(data)-1 && (data[valStart] == 0 && data[valStart+1] == 0) {
			valStart += 2
		}
		// Align to 4-byte boundary
		if valStart%4 != 0 {
			valStart += 4 - (valStart % 4)
		}
		if valStart >= len(data)-2 {
			return ""
		}
		// Read UTF-16LE value until null
		var u16 []uint16
		for j := valStart; j < len(data)-1 && j < valStart+512; j += 2 {
			ch := binary.LittleEndian.Uint16(data[j:])
			if ch == 0 {
				break
			}
			u16 = append(u16, ch)
		}
		if len(u16) > 0 {
			return string(utf16.Decode(u16))
		}
		return ""
	}
	return ""
}

func encodeUTF16LE(s string) []byte {
	runes := []rune(s)
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		buf[i*2] = byte(r)
		buf[i*2+1] = byte(r >> 8)
	}
	return buf
}
