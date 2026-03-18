package analyze

import (
	"debug/pe"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/arch/arm/armasm"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

const (
	defaultDisasmCount = 50
	maxDisasmCount     = 200
)

// opDisassemble disassembles machine code from a binary file.
// Supports x86 (16/32/64-bit) and ARM (32/64-bit).
// Reads only the needed portion instead of the entire file to save memory.
func opDisassemble(input AnalyzeInput) (string, error) {
	// VA-to-offset: auto-convert virtual address to file offset using PE headers
	var funcEndFileOff int64 = -1 // function boundary from .pdata (if available)
	var symbolMap map[uint64]string // VA -> symbol name for annotations
	if input.VA != "" {
		va, err := parseHexAddr(input.VA)
		if err != nil {
			return "", fmt.Errorf("invalid va: %s", input.VA)
		}
		f, err := pe.Open(input.FilePath)
		if err != nil {
			return "", fmt.Errorf("va parameter requires a PE file: %w", err)
		}
		defer f.Close()

		imageBase := peImageBase(f)
		if va < imageBase {
			return "", fmt.Errorf("va 0x%x is below image base 0x%x", va, imageBase)
		}
		if va-imageBase > 0xFFFFFFFF {
			return "", fmt.Errorf("va 0x%x is too far from image base 0x%x (RVA exceeds 4GB)", va, imageBase)
		}
		rva := uint32(va - imageBase)
		fileOff, _, err := rvaToFileOffset(f, rva)
		if err != nil {
			return "", fmt.Errorf("va 0x%x: %w", va, err)
		}
		input.Offset = int(fileOff)

		if input.BaseAddr == "" {
			// base_addr maps to file offset 0: displayed_addr = base_addr + fileOffset + pos
			// For correct VA display: base_addr = VA - fileOffset
			input.BaseAddr = fmt.Sprintf("0x%x", va-uint64(fileOff))
		}
		// Auto-detect CPU mode from PE Machine field
		if input.Mode == 0 {
			switch f.FileHeader.Machine {
			case 0x14c: // IMAGE_FILE_MACHINE_I386
				input.Mode = 32
			case 0x8664: // IMAGE_FILE_MACHINE_AMD64
				input.Mode = 64
			}
		}

		// Auto-stop at function boundary: .pdata first, heuristic fallback
		if endOff, _, found := pdataOrHeuristicEndOffset(f, rva, uint32(fileOff)); found {
			funcEndFileOff = int64(endOff)
		}

		// Build symbol map for inline annotations
		symbolMap = peSymbolMap(f, imageBase)
	}

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

	arch := strings.ToLower(strings.TrimSpace(input.Arch))
	if arch == "" {
		arch = "x86"
	}

	switch arch {
	case "x86":
		if mode != 16 && mode != 32 && mode != 64 {
			return "", fmt.Errorf("invalid mode for x86: %d (must be 16, 32, or 64)", mode)
		}
	case "arm":
		if mode != 32 && mode != 64 {
			return "", fmt.Errorf("invalid mode for arm: %d (must be 32 or 64)", mode)
		}
	default:
		return "", fmt.Errorf("unsupported arch: %s (available: x86, arm)", arch)
	}

	// Determine read size based on architecture
	// x86: up to 15 bytes per instruction, ARM: fixed 4 bytes per instruction
	var maxInstLen int64
	if arch == "arm" {
		maxInstLen = 4
	} else {
		maxInstLen = 15
	}
	readSize := int64(count) * maxInstLen
	if int64(offset)+readSize > fileSize {
		readSize = fileSize - int64(offset)
	}
	// Clamp read to function boundary from .pdata (prevents disassembly past function end)
	if funcEndFileOff > 0 && int64(offset) < funcEndFileOff {
		funcReadSize := funcEndFileOff - int64(offset)
		if funcReadSize < readSize {
			readSize = funcReadSize
		}
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

	switch arch {
	case "arm":
		if mode == 64 {
			return disasmARM64(data, baseAddr, offset, count)
		}
		return disasmARM32(data, baseAddr, offset, count)
	default:
		return disasmX86(data, baseAddr, offset, count, mode, symbolMap)
	}
}

// DisasmBytes disassembles raw machine code bytes.
// Exported for use by other packages (e.g., memtool for live process memory).
func DisasmBytes(data []byte, baseAddr uint64, arch string, mode int, count int) (string, error) {
	if count <= 0 {
		count = defaultDisasmCount
	}
	if count > maxDisasmCount {
		count = maxDisasmCount
	}
	if arch == "" {
		arch = "x86"
	}
	switch arch {
	case "arm":
		if mode == 64 {
			return disasmARM64(data, baseAddr, 0, count)
		}
		return disasmARM32(data, baseAddr, 0, count)
	default:
		if mode == 0 {
			mode = 64
		}
		return disasmX86(data, baseAddr, 0, count, mode, nil)
	}
}

func disasmX86(data []byte, baseAddr uint64, offset, count, mode int, symbols map[uint64]string) (string, error) {
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

		var hexParts []string
		for _, b := range instBytes {
			hexParts = append(hexParts, fmt.Sprintf("%02x", b))
		}
		hexStr := strings.Join(hexParts, " ")

		// Intel syntax with address context for RIP-relative resolution
		asmStr := x86asm.IntelSyntax(inst, addr, nil)

		// Symbol annotation: resolve target addresses to import/export names
		annotation := resolveSymbol(inst, addr, symbols, mode)
		if annotation != "" {
			sb.WriteString(fmt.Sprintf("0x%x:  %-30s %s  ; %s\n", addr, hexStr, asmStr, annotation))
		} else {
			sb.WriteString(fmt.Sprintf("0x%x:  %-30s %s\n", addr, hexStr, asmStr))
		}

		pos += inst.Len
		decoded++
	}

	sb.WriteString(fmt.Sprintf("\n(%d instructions from offset 0x%x, arch=x86, mode=%d)", decoded, offset, mode))
	return sb.String(), nil
}

func disasmARM64(data []byte, baseAddr uint64, offset, count int) (string, error) {
	var sb strings.Builder
	decoded := 0

	// ARM64 instructions are fixed 4 bytes
	for pos := 0; decoded < count && pos+4 <= len(data); pos += 4 {
		addr := baseAddr + uint64(offset) + uint64(pos)

		inst, err := arm64asm.Decode(data[pos : pos+4])
		if err != nil {
			sb.WriteString(fmt.Sprintf("0x%x:  %02x %02x %02x %02x                   .word 0x%08x\n",
				addr, data[pos], data[pos+1], data[pos+2], data[pos+3],
				uint32(data[pos])|uint32(data[pos+1])<<8|uint32(data[pos+2])<<16|uint32(data[pos+3])<<24))
			decoded++
			continue
		}

		hexStr := fmt.Sprintf("%02x %02x %02x %02x", data[pos], data[pos+1], data[pos+2], data[pos+3])
		asmStr := inst.String()

		sb.WriteString(fmt.Sprintf("0x%x:  %-30s %s\n", addr, hexStr, asmStr))
		decoded++
	}

	sb.WriteString(fmt.Sprintf("\n(%d instructions from offset 0x%x, arch=arm, mode=64)", decoded, offset))
	return sb.String(), nil
}

func disasmARM32(data []byte, baseAddr uint64, offset, count int) (string, error) {
	var sb strings.Builder
	decoded := 0

	// ARM32 instructions are fixed 4 bytes (ARM mode, not Thumb)
	for pos := 0; decoded < count && pos+4 <= len(data); pos += 4 {
		addr := baseAddr + uint64(offset) + uint64(pos)

		inst, err := armasm.Decode(data[pos:pos+4], armasm.ModeARM)
		if err != nil {
			sb.WriteString(fmt.Sprintf("0x%x:  %02x %02x %02x %02x                   .word 0x%08x\n",
				addr, data[pos], data[pos+1], data[pos+2], data[pos+3],
				uint32(data[pos])|uint32(data[pos+1])<<8|uint32(data[pos+2])<<16|uint32(data[pos+3])<<24))
			decoded++
			continue
		}

		hexStr := fmt.Sprintf("%02x %02x %02x %02x", data[pos], data[pos+1], data[pos+2], data[pos+3])
		asmStr := inst.String()

		sb.WriteString(fmt.Sprintf("0x%x:  %-30s %s\n", addr, hexStr, asmStr))
		decoded++
	}

	sb.WriteString(fmt.Sprintf("\n(%d instructions from offset 0x%x, arch=arm, mode=32)", decoded, offset))
	return sb.String(), nil
}

// resolveSymbol looks up target addresses in the symbol map for CALL/JMP/LEA instructions.
// Returns the symbol name if found, empty string otherwise.
func resolveSymbol(inst x86asm.Inst, instrAddr uint64, symbols map[uint64]string, mode int) string {
	if len(symbols) == 0 {
		return ""
	}

	nextAddr := instrAddr + uint64(inst.Len)

	for _, arg := range inst.Args {
		if arg == nil {
			break
		}
		switch a := arg.(type) {
		case x86asm.Rel:
			// E8/E9 relative CALL/JMP: target = instrAddr + instLen + rel
			target := nextAddr + uint64(int64(a))
			if name, ok := symbols[target]; ok {
				return name
			}
		case x86asm.Mem:
			// RIP-relative memory: FF 15 [rip+disp32], LEA reg, [rip+disp32]
			if mode == 64 && a.Base == x86asm.RIP && a.Index == 0 && a.Scale == 0 {
				target := nextAddr + uint64(int64(a.Disp))
				if name, ok := symbols[target]; ok {
					return name
				}
			}
		case x86asm.Imm:
			// Immediate address (32-bit mode): PUSH addr, CALL addr
			target := uint64(a)
			if name, ok := symbols[target]; ok {
				return name
			}
		}
	}
	return ""
}
