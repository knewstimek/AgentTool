package analyze

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

const (
	defaultDisasmCount = 50
	maxDisasmCount     = 200
)

// opDisassemble disassembles x86/x64 machine code from a binary file.
// Reads only the needed portion instead of the entire file to save memory.
func opDisassemble(input AnalyzeInput) (string, error) {
	fi, err := os.Stat(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("cannot access file: %w", err)
	}
	fileSize := fi.Size()

	offset := input.Offset
	if offset < 0 || int64(offset) >= fileSize {
		return "", fmt.Errorf("offset %d out of range (file size: %d)", offset, fileSize)
	}

	count := input.Count
	if count <= 0 {
		count = defaultDisasmCount
	}
	if count > maxDisasmCount {
		count = maxDisasmCount
	}

	mode := input.Mode
	if mode == 0 {
		mode = 64
	}
	if mode != 16 && mode != 32 && mode != 64 {
		return "", fmt.Errorf("invalid mode: %d (must be 16, 32, or 64)", mode)
	}

	// Read only the needed portion: count * 15 (max x86 instruction length)
	// This avoids loading entire 50MB files when only a small section is needed.
	readSize := int64(count) * 15
	if int64(offset)+readSize > fileSize {
		readSize = fileSize - int64(offset)
	}
	f, err := os.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("cannot open file: %w", err)
	}
	defer f.Close()
	data := make([]byte, readSize)
	// ReadAt returns io.EOF when fewer bytes are available than requested
	// (e.g. near end of file). Partial data is still valid, so ignore EOF.
	if _, err := f.ReadAt(data, int64(offset)); err != nil && err.Error() != "EOF" {
		return "", fmt.Errorf("cannot read file: %w", err)
	}

	// Parse base address for display
	var baseAddr uint64
	if input.BaseAddr != "" {
		ba := strings.TrimPrefix(input.BaseAddr, "0x")
		ba = strings.TrimPrefix(ba, "0X")
		baseAddr, err = strconv.ParseUint(ba, 16, 64)
		if err != nil {
			return "", fmt.Errorf("invalid base_addr: %s", input.BaseAddr)
		}
	}

	var sb strings.Builder
	pos := 0
	decoded := 0

	for decoded < count && pos < len(data) {
		inst, err := x86asm.Decode(data[pos:], mode)
		if err != nil {
			// Failed to decode — emit raw byte and skip
			addr := baseAddr + uint64(offset) + uint64(pos)
			sb.WriteString(fmt.Sprintf("0x%x:  %02x                          db 0x%02x\n",
				addr, data[pos], data[pos]))
			pos++
			decoded++
			continue
		}

		addr := baseAddr + uint64(offset) + uint64(pos)
		instBytes := data[pos : pos+inst.Len]

		// Format hex bytes (padded to ~30 chars for alignment)
		var hexParts []string
		for _, b := range instBytes {
			hexParts = append(hexParts, fmt.Sprintf("%02x", b))
		}
		hexStr := strings.Join(hexParts, " ")

		// Intel syntax with address context for RIP-relative resolution
		asmStr := x86asm.IntelSyntax(inst, addr, nil)

		sb.WriteString(fmt.Sprintf("0x%x:  %-30s %s\n", addr, hexStr, asmStr))

		pos += inst.Len
		decoded++
	}

	sb.WriteString(fmt.Sprintf("\n(%d instructions from offset 0x%x, mode=%d)", decoded, offset, mode))

	return sb.String(), nil
}
