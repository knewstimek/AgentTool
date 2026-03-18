package analyze

import (
	"fmt"
	"os"
	"strings"
)

const (
	defaultHexdumpLength = 256
	maxHexdumpLength     = 4096
	bytesPerLine         = 16
)

// opHexdump displays a hex+ASCII dump of a file region.
func opHexdump(input AnalyzeInput) (string, error) {
	f, err := os.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("cannot open file: %w", err)
	}
	defer f.Close()

	offset := int64(input.Offset)
	displayBase := uint64(0) // base address for display (file offset by default)

	// VA parameter: convert VA to file offset for PE files
	if input.VA != "" {
		resolved, err := resolveVA(input.FilePath, input.VA)
		if err != nil {
			return "", err
		}
		defer resolved.PEFile.Close()
		offset = resolved.FileOffset
		displayBase = resolved.DisplayBase
	}

	if offset < 0 {
		return "", fmt.Errorf("offset must be non-negative")
	}

	length := input.Length
	if length <= 0 {
		length = defaultHexdumpLength
	}
	if length > maxHexdumpLength {
		length = maxHexdumpLength
	}

	// Seek to offset
	if _, err := f.Seek(offset, 0); err != nil {
		return "", fmt.Errorf("cannot seek to offset 0x%x: %w", offset, err)
	}

	buf := make([]byte, length)
	// Only fail if no bytes were read; partial read at EOF is valid data
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return "", fmt.Errorf("cannot read at offset 0x%x: %w", offset, err)
	}
	buf = buf[:n]

	var sb strings.Builder

	for i := 0; i < n; i += bytesPerLine {
		addr := displayBase + uint64(offset) + uint64(i)

		// Hex part
		var hexParts []string
		for j := 0; j < bytesPerLine; j++ {
			if i+j < n {
				hexParts = append(hexParts, fmt.Sprintf("%02x", buf[i+j]))
			} else {
				hexParts = append(hexParts, "  ")
			}
		}

		// Group hex bytes with extra space in the middle for readability
		hexLeft := strings.Join(hexParts[:8], " ")
		hexRight := strings.Join(hexParts[8:], " ")

		// ASCII part
		var ascii strings.Builder
		for j := 0; j < bytesPerLine && i+j < n; j++ {
			b := buf[i+j]
			if b >= 0x20 && b <= 0x7E {
				ascii.WriteByte(b)
			} else {
				ascii.WriteByte('.')
			}
		}

		sb.WriteString(fmt.Sprintf("0x%08x  %s  %s  |%s|\n", addr, hexLeft, hexRight, ascii.String()))
	}

	if displayBase != 0 {
		sb.WriteString(fmt.Sprintf("\n(%d bytes from VA 0x%x, file offset 0x%x)", n, displayBase+uint64(offset), offset))
	} else {
		sb.WriteString(fmt.Sprintf("\n(%d bytes from offset 0x%x)", n, offset))
	}

	return sb.String(), nil
}
