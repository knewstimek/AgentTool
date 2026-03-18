package analyze

import (
	"debug/pe"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

// peVAMapper provides file-offset-to-VA conversion for PE files.
// nil means no PE mapping (non-PE file or parse failure).
type peVAMapper struct {
	file      *pe.File
	imageBase uint64
}

// toVA converts a file offset to a VA string. Returns "" if unmappable.
func (m *peVAMapper) toVA(fileOff int) string {
	if m == nil {
		return ""
	}
	rva, ok := fileOffsetToRVA(m.file, uint32(fileOff))
	if !ok {
		return ""
	}
	return fmt.Sprintf("0x%x", m.imageBase+uint64(rva))
}

// tryPEMapper attempts to open the file as PE and create a VA mapper.
func tryPEMapper(filePath string) *peVAMapper {
	f, err := pe.Open(filePath)
	if err != nil {
		return nil
	}
	ib := peImageBase(f)
	if ib == 0 {
		f.Close()
		return nil
	}
	return &peVAMapper{file: f, imageBase: ib}
}

func (m *peVAMapper) close() {
	if m != nil && m.file != nil {
		m.file.Close()
	}
}

const (
	defaultMinLength  = 4
	defaultMaxResults = 500
	maxMaxResults     = 2000
)

// opStrings extracts printable strings from a binary file.
// Supports ASCII (0x20-0x7E) and UTF-8 modes.
func opStrings(input AnalyzeInput) (string, error) {
	data, err := os.ReadFile(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("cannot read file: %w", err)
	}

	minLen := input.MinLength
	if minLen <= 0 {
		minLen = defaultMinLength
	}

	maxRes := input.MaxResults
	if maxRes <= 0 {
		maxRes = defaultMaxResults
	}
	if maxRes > maxMaxResults {
		maxRes = maxMaxResults
	}

	enc := strings.ToLower(strings.TrimSpace(input.Encoding))
	if enc == "" {
		enc = "ascii"
	}

	// PE VA mapping: show VA alongside file offset for PE files
	mapper := tryPEMapper(input.FilePath)
	defer mapper.close()

	var sb strings.Builder
	var found int

	switch enc {
	case "ascii":
		found = extractASCII(data, minLen, maxRes, mapper, &sb)
	case "utf8", "utf-8":
		found = extractUTF8(data, minLen, maxRes, mapper, &sb)
	default:
		return "", fmt.Errorf("unsupported encoding: %s (use ascii or utf8)", enc)
	}

	sb.WriteString(fmt.Sprintf("\n(%d strings found, min_length=%d, encoding=%s)", found, minLen, enc))
	if found >= maxRes {
		sb.WriteString(fmt.Sprintf(" -- truncated at max_results=%d", maxRes))
	}

	return sb.String(), nil
}

// extractASCII finds runs of printable ASCII characters (0x20-0x7E).
func extractASCII(data []byte, minLen, maxRes int, mapper *peVAMapper, sb *strings.Builder) int {
	found := 0
	start := -1

	for i, b := range data {
		if b >= 0x20 && b <= 0x7E {
			if start < 0 {
				start = i
			}
		} else {
			if start >= 0 {
				length := i - start
				if length >= minLen {
					writeStringEntry(sb, start, string(data[start:i]), mapper)
					found++
					if found >= maxRes {
						return found
					}
				}
				start = -1
			}
		}
	}
	// Handle string at end of file
	if start >= 0 {
		length := len(data) - start
		if length >= minLen {
			writeStringEntry(sb, start, string(data[start:]), mapper)
			found++
		}
	}
	return found
}

// extractUTF8 finds runs of valid UTF-8 characters (excluding control chars).
// This catches non-ASCII strings like CJK, Cyrillic, etc.
func extractUTF8(data []byte, minLen, maxRes int, mapper *peVAMapper, sb *strings.Builder) int {
	found := 0
	start := -1
	charCount := 0 // count in runes, not bytes
	i := 0

	for i < len(data) {
		r, size := utf8.DecodeRune(data[i:])
		// Valid UTF-8 rune that is printable (not control, not replacement)
		if r != utf8.RuneError && size > 0 && isPrintableRune(r) {
			if start < 0 {
				start = i
				charCount = 0
			}
			charCount++
			i += size
		} else {
			if start >= 0 && charCount >= minLen {
				writeStringEntry(sb, start, string(data[start:i]), mapper)
				found++
				if found >= maxRes {
					return found
				}
			}
			start = -1
			charCount = 0
			i++
		}
	}
	if start >= 0 && charCount >= minLen {
		writeStringEntry(sb, start, string(data[start:]), mapper)
		found++
	}
	return found
}

// writeStringEntry formats a string entry with optional VA mapping for PE files.
func writeStringEntry(sb *strings.Builder, fileOff int, s string, mapper *peVAMapper) {
	va := mapper.toVA(fileOff)
	if va != "" {
		sb.WriteString(fmt.Sprintf("0x%06x (%s): %s\n", fileOff, va, s))
	} else {
		sb.WriteString(fmt.Sprintf("0x%06x: %s\n", fileOff, s))
	}
}

// isPrintableRune returns true for printable characters (excluding ASCII control chars).
func isPrintableRune(r rune) bool {
	// Allow space (0x20) through tilde (0x7E) and all non-ASCII Unicode
	if r >= 0x20 && r <= 0x7E {
		return true
	}
	// Tab is useful in strings
	if r == '\t' {
		return true
	}
	// Non-ASCII printable (CJK, Cyrillic, Arabic, etc.)
	return r > 0x7F
}
