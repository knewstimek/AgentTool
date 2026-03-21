package analyze

import (
	"agent-tool/common"
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
)

const entropyChunkSize = 64 * 1024 // 64KB read buffer

// opEntropy calculates Shannon entropy for file sections or the whole file.
// High entropy (>7.0) suggests compressed or encrypted data.
// Low entropy (<1.0) suggests padding or uninitialized data.
func opEntropy(input AnalyzeInput) (string, error) {
	// entropy reads entire file into memory -- enforce size limit
	maxSize := int64(common.GetMaxFileSize())
	if fi, err := os.Stat(input.FilePath); err == nil && fi.Size() > maxSize {
		return "", fmt.Errorf("file too large for entropy: %d bytes (max %d MB, change with set_config max_file_size_mb)",
			fi.Size(), maxSize/(1024*1024))
	}
	data, err := os.ReadFile(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("cannot read file: %w", err)
	}

	var sb strings.Builder

	// Whole-file entropy
	wholeEntropy := shannonEntropy(data)
	sb.WriteString(fmt.Sprintf("File: %s\n", input.FilePath))
	sb.WriteString(fmt.Sprintf("Size: %d bytes\n", len(data)))
	sb.WriteString(fmt.Sprintf("Overall Entropy: %.4f / 8.0 %s\n\n", wholeEntropy, entropyLabel(wholeEntropy)))

	// Detect binary format from already-loaded data to avoid TOCTOU
	// (re-opening the file could read different content if modified between reads)
	sections := detectSections(data)
	if len(sections) > 0 {
		sb.WriteString(fmt.Sprintf("Per-Section Entropy (%d sections):\n", len(sections)))
		sb.WriteString(fmt.Sprintf("  %-20s %-12s %-12s %-10s %s\n",
			"Name", "Offset", "Size", "Entropy", ""))

		for _, sec := range sections {
			if sec.offset+sec.size > uint64(len(data)) {
				continue
			}
			if sec.size == 0 {
				sb.WriteString(fmt.Sprintf("  %-20s 0x%-10x %-12d %-10s (empty)\n",
					sec.name, sec.offset, sec.size, "-"))
				continue
			}
			secData := data[sec.offset : sec.offset+sec.size]
			e := shannonEntropy(secData)
			sb.WriteString(fmt.Sprintf("  %-20s 0x%-10x %-12d %-10.4f %s\n",
				sec.name, sec.offset, sec.size, e, entropyLabel(e)))
		}
	} else {
		// No recognized format — show block-based entropy
		sb.WriteString("No recognized binary format detected. Showing block entropy:\n")
		blockSize := 4096
		sb.WriteString(fmt.Sprintf("  %-12s %-12s %-10s %s\n", "Offset", "Size", "Entropy", ""))

		for off := 0; off < len(data); off += blockSize {
			end := off + blockSize
			if end > len(data) {
				end = len(data)
			}
			block := data[off:end]
			e := shannonEntropy(block)
			sb.WriteString(fmt.Sprintf("  0x%-10x %-12d %-10.4f %s\n",
				off, len(block), e, entropyLabel(e)))
		}
	}

	return sb.String(), nil
}

// shannonEntropy calculates the Shannon entropy of data in bits per byte (0-8).
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}

	n := float64(len(data))
	entropy := 0.0
	for _, count := range freq {
		if count > 0 {
			p := count / n
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func entropyLabel(e float64) string {
	switch {
	case e < 1.0:
		return "(very low — padding/zeroes)"
	case e < 3.0:
		return "(low — structured data)"
	case e < 5.0:
		return "(medium — code/text)"
	case e < 7.0:
		return "(high — compiled code)"
	case e < 7.9:
		return "(very high — compressed/encrypted?)"
	default:
		return "(near-max — encrypted/random)"
	}
}

type binarySection struct {
	name   string
	offset uint64
	size   uint64
}

// detectSections tries PE, ELF, then Mach-O to extract section info.
// Uses in-memory data (bytes.NewReader) instead of re-opening the file
// to avoid TOCTOU issues.
func detectSections(data []byte) []binarySection {
	r := bytes.NewReader(data)

	// Try PE
	if sections := detectPESections(r); len(sections) > 0 {
		return sections
	}
	r.Seek(0, io.SeekStart)
	// Try ELF
	if sections := detectELFSections(r, int64(len(data))); len(sections) > 0 {
		return sections
	}
	r.Seek(0, io.SeekStart)
	// Try Mach-O
	if sections := detectMachOSections(r); len(sections) > 0 {
		return sections
	}
	return nil
}

func detectPESections(r io.ReaderAt) []binarySection {
	f, err := pe.NewFile(r)
	if err != nil {
		return nil
	}
	defer f.Close()

	var sections []binarySection
	for _, s := range f.Sections {
		sections = append(sections, binarySection{
			name:   s.Name,
			offset: uint64(s.Offset),
			size:   uint64(s.Size),
		})
	}
	return sections
}

func detectELFSections(r io.ReaderAt, size int64) []binarySection {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil
	}
	defer f.Close()

	var sections []binarySection
	for _, s := range f.Sections {
		// Skip sections with no file data
		if s.Type == elf.SHT_NOBITS {
			continue
		}
		sections = append(sections, binarySection{
			name:   s.Name,
			offset: s.Offset,
			size:   s.Size,
		})
	}
	return sections
}

func detectMachOSections(r io.ReaderAt) []binarySection {
	f, err := macho.NewFile(r)
	if err != nil {
		return nil
	}
	defer f.Close()

	var sections []binarySection
	for _, s := range f.Sections {
		sections = append(sections, binarySection{
			name:   fmt.Sprintf("%s/%s", s.Seg, s.Name),
			offset: uint64(s.Offset),
			size:   s.Size,
		})
	}
	return sections
}
