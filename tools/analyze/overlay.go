package analyze

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"os"
	"strings"
)

// opOverlayDetect checks if a binary has data appended after the last
// section/segment. Common in packed executables, droppers, and self-extracting
// archives where the payload is concatenated to the PE/ELF.
func opOverlayDetect(input AnalyzeInput) (string, error) {
	fi, err := os.Stat(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("cannot stat file: %w", err)
	}
	fileSize := fi.Size()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("File: %s\n", input.FilePath))
	sb.WriteString(fmt.Sprintf("File Size: %d bytes (0x%x)\n", fileSize, fileSize))

	// Try PE, ELF, Mach-O in order
	lastByte, format, err := detectLastSectionEnd(input.FilePath)
	if err != nil {
		return "", err
	}

	sb.WriteString(fmt.Sprintf("Format: %s\n", format))
	sb.WriteString(fmt.Sprintf("Last Section End: 0x%x (%d bytes)\n", lastByte, lastByte))

	overlaySize := fileSize - lastByte
	if lastByte > fileSize {
		sb.WriteString(fmt.Sprintf("\n⚠ TRUNCATED: sections claim %d bytes but file is only %d bytes (missing %d bytes)\n",
			lastByte, fileSize, lastByte-fileSize))
		return sb.String(), nil
	}
	if overlaySize > 0 {
		sb.WriteString(fmt.Sprintf("\n⚠ OVERLAY DETECTED: %d bytes (0x%x) after last section\n", overlaySize, overlaySize))
		sb.WriteString(fmt.Sprintf("Overlay Offset: 0x%x\n", lastByte))
		pct := float64(overlaySize) / float64(fileSize) * 100
		sb.WriteString(fmt.Sprintf("Overlay is %.1f%% of total file size\n", pct))

		// Show first few bytes of overlay for quick identification
		f, err := os.Open(input.FilePath)
		if err == nil {
			defer f.Close()
			preview := make([]byte, 64)
			n, _ := f.ReadAt(preview, lastByte)
			if n > 0 {
				sb.WriteString(fmt.Sprintf("\nOverlay preview (first %d bytes):\n", n))
				sb.WriteString(formatHexPreview(preview[:n], uint64(lastByte)))
			}
		}

		// Check for common signatures
		if sig := identifyOverlay(input.FilePath, lastByte); sig != "" {
			sb.WriteString(fmt.Sprintf("\nSignature: %s\n", sig))
		}
	} else {
		sb.WriteString("\nNo overlay detected — file ends exactly at last section boundary.")
	}

	return sb.String(), nil
}

func detectLastSectionEnd(path string) (int64, string, error) {
	// Try PE
	if end, err := peLastSectionEnd(path); err == nil {
		return end, "PE", nil
	}
	// Try ELF
	if end, err := elfLastSectionEnd(path); err == nil {
		return end, "ELF", nil
	}
	// Try Mach-O
	if end, err := machoLastSectionEnd(path); err == nil {
		return end, "Mach-O", nil
	}
	return 0, "", fmt.Errorf("not a recognized binary format (PE, ELF, or Mach-O)")
}

func peLastSectionEnd(path string) (int64, error) {
	f, err := pe.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var maxEnd int64
	for _, s := range f.Sections {
		end := int64(s.Offset) + int64(s.Size)
		if end > maxEnd {
			maxEnd = end
		}
	}

	// Certificate table (data directory index 4) sits after sections.
	// Unlike other data directories, CertTable's VirtualAddress field is actually
	// a raw file offset (not an RVA) per the PE specification.
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 4 {
			certEnd := int64(oh.DataDirectory[4].VirtualAddress) + int64(oh.DataDirectory[4].Size)
			if certEnd > maxEnd {
				maxEnd = certEnd
			}
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 4 {
			certEnd := int64(oh.DataDirectory[4].VirtualAddress) + int64(oh.DataDirectory[4].Size)
			if certEnd > maxEnd {
				maxEnd = certEnd
			}
		}
	}

	if maxEnd == 0 {
		return 0, fmt.Errorf("no sections found")
	}
	return maxEnd, nil
}

func elfLastSectionEnd(path string) (int64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var maxEnd int64
	for _, s := range f.Sections {
		if s.Type == elf.SHT_NOBITS {
			continue
		}
		end := int64(s.Offset) + int64(s.Size)
		if end > maxEnd {
			maxEnd = end
		}
	}
	if maxEnd == 0 {
		return 0, fmt.Errorf("no sections found")
	}
	return maxEnd, nil
}

func machoLastSectionEnd(path string) (int64, error) {
	f, err := macho.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var maxEnd int64
	for _, load := range f.Loads {
		if seg, ok := load.(*macho.Segment); ok {
			end := int64(seg.Offset) + int64(seg.Filesz)
			if end > maxEnd {
				maxEnd = end
			}
		}
	}
	if maxEnd == 0 {
		return 0, fmt.Errorf("no segments found")
	}
	return maxEnd, nil
}

func formatHexPreview(data []byte, baseAddr uint64) string {
	var sb strings.Builder
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		row := data[i:end]

		// Hex
		var hexParts []string
		for _, b := range row {
			hexParts = append(hexParts, fmt.Sprintf("%02x", b))
		}
		for len(hexParts) < 16 {
			hexParts = append(hexParts, "  ")
		}

		// ASCII
		var ascii strings.Builder
		for _, b := range row {
			if b >= 0x20 && b <= 0x7E {
				ascii.WriteByte(b)
			} else {
				ascii.WriteByte('.')
			}
		}

		sb.WriteString(fmt.Sprintf("  0x%08x  %s  |%s|\n",
			baseAddr+uint64(i),
			strings.Join(hexParts[:8], " ")+"  "+strings.Join(hexParts[8:], " "),
			ascii.String()))
	}
	return sb.String()
}

// identifyOverlay checks common signatures at the overlay start.
func identifyOverlay(path string, offset int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	sig := make([]byte, 4)
	if _, err := f.ReadAt(sig, offset); err != nil {
		return ""
	}

	// Check common signatures
	switch {
	case sig[0] == 'P' && sig[1] == 'K' && sig[2] == 0x03 && sig[3] == 0x04:
		return "ZIP archive (PK header) — possible self-extracting archive"
	case sig[0] == 0x1F && sig[1] == 0x8B:
		return "GZIP compressed data"
	case sig[0] == 'R' && sig[1] == 'a' && sig[2] == 'r' && sig[3] == '!':
		return "RAR archive"
	case sig[0] == 0x37 && sig[1] == 0x7A && sig[2] == 0xBC && sig[3] == 0xAF:
		return "7-Zip archive"
	case sig[0] == 'M' && sig[1] == 'Z':
		return "PE executable (nested/embedded binary)"
	case sig[0] == 0x7F && sig[1] == 'E' && sig[2] == 'L' && sig[3] == 'F':
		return "ELF binary (embedded)"
	case sig[0] == 0xCA && sig[1] == 0xFE && sig[2] == 0xBA && sig[3] == 0xBE:
		return "Mach-O fat binary (embedded)"
	case sig[0] == 0xFE && sig[1] == 0xED && sig[2] == 0xFA:
		return "Mach-O binary (embedded)"
	}
	return ""
}
