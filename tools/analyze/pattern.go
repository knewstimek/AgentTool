package analyze

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

const (
	defaultPatternMaxResults = 100
	maxPatternMaxResults     = 500
	// Read file in chunks to avoid loading huge files into memory.
	// Overlap equals max pattern byte length to catch matches at boundaries.
	patternChunkSize = 4 * 1024 * 1024 // 4MB
	patternOverlap   = 256
)

// opPatternSearch searches a binary file for a hex byte pattern with wildcard support.
// Pattern format: hex bytes separated by spaces, "??" for any byte.
// Example: "4D 5A ?? ?? 50 45" matches MZ header with any 2 bytes before PE.
func opPatternSearch(input AnalyzeInput) (string, error) {
	pattern := strings.TrimSpace(input.Pattern)
	if pattern == "" {
		return "", fmt.Errorf("pattern is required (hex bytes, e.g. '4D 5A ?? ?? 50 45')")
	}

	patternBytes, mask, err := parseHexPattern(pattern)
	if err != nil {
		return "", err
	}
	if len(patternBytes) == 0 {
		return "", fmt.Errorf("pattern is empty after parsing")
	}

	maxRes := input.MaxResults
	if maxRes <= 0 {
		maxRes = defaultPatternMaxResults
	}
	if maxRes > maxPatternMaxResults {
		maxRes = maxPatternMaxResults
	}

	f, err := os.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("cannot open file: %w", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("cannot stat file: %w", err)
	}
	fileSize := fi.Size()

	// PE VA mapping: show VA alongside file offset for PE files
	mapper := tryPEMapper(input.FilePath)
	defer mapper.close()

	var sb strings.Builder
	found := 0

	// Section name resolver for PE files
	var peSections []peSectionRange
	if mapper != nil {
		for _, s := range mapper.file.Sections {
			peSections = append(peSections, peSectionRange{
				name:  s.Name,
				start: s.Offset,
				end:   s.Offset + s.Size,
			})
		}
	}
	patLen := len(patternBytes)

	// Chunked reading with overlap to catch matches spanning chunk boundaries
	buf := make([]byte, patternChunkSize+patternOverlap)
	fileOffset := int64(0)

	for fileOffset < fileSize && found < maxRes {
		readSize := int64(patternChunkSize + patternOverlap)
		if fileOffset+readSize > fileSize {
			readSize = fileSize - fileOffset
		}

		n, err := f.ReadAt(buf[:readSize], fileOffset)
		if err != nil && n == 0 {
			break
		}
		chunk := buf[:n]

		// Search this chunk
		for i := 0; i <= len(chunk)-patLen; i++ {
			// Don't report matches in the overlap zone of the previous chunk
			absOffset := fileOffset + int64(i)
			if fileOffset > 0 && i < patternOverlap {
				continue
			}

			if matchPattern(chunk[i:i+patLen], patternBytes, mask) {
				// Show matched bytes with optional VA and section name for PE files
				matchHex := hex.EncodeToString(chunk[i : i+patLen])
				va := mapper.toVA(int(absOffset))
				var secName string
				if absOffset <= 0xFFFFFFFF {
					secName = sectionForFileOffset(peSections, uint32(absOffset))
				}
				if va != "" {
					if secName != "" {
						sb.WriteString(fmt.Sprintf("[%s] 0x%08x (%s): %s\n", secName, absOffset, va, formatHexSpaced(matchHex)))
					} else {
						sb.WriteString(fmt.Sprintf("0x%08x (%s): %s\n", absOffset, va, formatHexSpaced(matchHex)))
					}
				} else {
					sb.WriteString(fmt.Sprintf("0x%08x: %s\n", absOffset, formatHexSpaced(matchHex)))
				}
				found++
				if found >= maxRes {
					break
				}
			}
		}

		// Advance by chunk size (not chunk+overlap) so overlap region is re-scanned
		fileOffset += patternChunkSize
	}

	sb.WriteString(fmt.Sprintf("\n(%d matches found for pattern '%s')", found, pattern))
	if found >= maxRes {
		sb.WriteString(fmt.Sprintf(" -- truncated at max_results=%d", maxRes))
	}

	return sb.String(), nil
}

// parseHexPattern parses "4D 5A ?? 00" into byte slice and mask.
// mask[i]==true means patternBytes[i] must match; false means wildcard.
func parseHexPattern(pattern string) ([]byte, []bool, error) {
	tokens := strings.Fields(pattern)
	if len(tokens) == 0 {
		return nil, nil, fmt.Errorf("empty pattern")
	}
	// Pattern must be shorter than overlap to guarantee matches at chunk boundaries
	if len(tokens) >= patternOverlap {
		return nil, nil, fmt.Errorf("pattern too long (max %d bytes)", patternOverlap-1)
	}

	patternBytes := make([]byte, len(tokens))
	mask := make([]bool, len(tokens))

	for i, tok := range tokens {
		if tok == "??" || tok == "?" {
			patternBytes[i] = 0
			mask[i] = false
		} else {
			b, err := hex.DecodeString(tok)
			if err != nil || len(b) != 1 {
				return nil, nil, fmt.Errorf("invalid hex byte at position %d: '%s' (expected 2-digit hex or '??')", i, tok)
			}
			patternBytes[i] = b[0]
			mask[i] = true
		}
	}

	return patternBytes, mask, nil
}

// matchPattern checks if data matches pattern with wildcard mask.
func matchPattern(data, pattern []byte, mask []bool) bool {
	for i := range pattern {
		if mask[i] && data[i] != pattern[i] {
			return false
		}
	}
	return true
}

// peSectionRange maps file offset ranges to section names.
type peSectionRange struct {
	name  string
	start uint32
	end   uint32
}

// sectionForFileOffset returns the section name for a given file offset.
func sectionForFileOffset(sections []peSectionRange, off uint32) string {
	for _, s := range sections {
		if off >= s.start && off < s.end {
			return s.name
		}
	}
	return ""
}

// formatHexSpaced inserts spaces every 2 hex chars for readability.
func formatHexSpaced(h string) string {
	var parts []string
	for i := 0; i < len(h); i += 2 {
		end := i + 2
		if end > len(h) {
			end = len(h)
		}
		parts = append(parts, h[i:end])
	}
	return strings.Join(parts, " ")
}
