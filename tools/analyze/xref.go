package analyze

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	defaultXrefMaxResults = 200
	maxXrefMaxResults     = 1000
)

// xrefSection holds a code section's data and base address for xref scanning.
type xrefSection struct {
	data []byte
	// For x86/x64: offset from imageBase (RVA).
	// For ARM: offset from imageBase (RVA) or absolute VA depending on format.
	rva uint32
}

// xrefBinary holds the info needed to scan for cross-references in any binary format.
type xrefBinary struct {
	imageBase uint64
	arch      string // "x86", "x64", "arm64", "arm32"
	sections  []xrefSection
	format    string // "PE", "ELF", "Mach-O"
}

// xrefResult holds a single cross-reference result with type classification.
type xrefResult struct {
	refType string // CALL, JMP, LEA, MOV, PUSH, Jcc, BL, B, ADRP
	line    string // formatted output line
}

// opXref finds all code locations that reference a target virtual address.
// Supports PE, ELF, and Mach-O binaries with x86, x64, ARM64, and ARM32 architectures.
//
// Performance: full-scans all executable sections on every call (no caching).
// This is fast enough in practice (10MB binary in ~10ms) because the scan is
// simple byte-pattern matching, not instruction-level decoding. Unlike call_graph
// which collects ALL call targets (high false-positive risk from data bytes),
// xref matches against a specific target address, so false positives are
// statistically negligible (~1/2^32 chance per byte).
func opXref(input AnalyzeInput) (string, error) {
	if input.TargetVA == "" {
		return "", fmt.Errorf("target_va is required for xref")
	}

	targetVA, err := parseHexAddr(input.TargetVA)
	if err != nil {
		return "", fmt.Errorf("invalid target_va: %s", input.TargetVA)
	}

	// Try PE, then ELF, then Mach-O
	bin, err := xrefOpenPE(input.FilePath)
	if err != nil {
		bin, err = xrefOpenELF(input.FilePath)
	}
	if err != nil {
		bin, err = xrefOpenMachO(input.FilePath)
	}
	if err != nil {
		return "", fmt.Errorf("xref: not a valid PE, ELF, or Mach-O file: %w", err)
	}

	if targetVA < bin.imageBase {
		return "", fmt.Errorf("target_va 0x%x is below image base 0x%x", targetVA, bin.imageBase)
	}
	if targetVA-bin.imageBase > 0xFFFFFFFF {
		return "", fmt.Errorf("target_va 0x%x is too far from image base 0x%x (offset exceeds 4GB)", targetVA, bin.imageBase)
	}
	targetRVA := uint32(targetVA - bin.imageBase)

	maxRes := input.MaxResults
	if maxRes <= 0 {
		maxRes = defaultXrefMaxResults
	}
	if maxRes > maxXrefMaxResults {
		maxRes = maxXrefMaxResults
	}

	var refs []xrefResult
	found := 0

	for _, sec := range bin.sections {
		if found >= maxRes {
			break
		}
		switch bin.arch {
		case "x64":
			refs, found = collectXref64(sec.data, sec.rva, targetRVA, bin.imageBase, maxRes, found, refs)
		case "x86":
			refs, found = collectXref32(sec.data, sec.rva, targetRVA, bin.imageBase, maxRes, found, refs)
		case "arm64":
			refs, found = collectXrefARM64(sec.data, sec.rva, targetRVA, bin.imageBase, maxRes, found, refs)
		case "arm32":
			refs, found = collectXrefARM32(sec.data, sec.rva, targetRVA, bin.imageBase, maxRes, found, refs)
		}
	}

	var sb strings.Builder

	// Header with format/arch info
	archLabel := bin.arch
	if bin.format != "" {
		archLabel = bin.format + "/" + bin.arch
	}

	// Summary statistics
	if found > 0 {
		counts := make(map[string]int)
		for _, r := range refs {
			counts[r.refType]++
		}
		sb.WriteString(fmt.Sprintf("%d references to 0x%x (%s):", found, targetVA, archLabel))
		for _, typ := range []string{"CALL", "JMP", "LEA", "MOV", "PUSH", "Jcc", "BL", "B", "ADRP"} {
			if c, ok := counts[typ]; ok {
				sb.WriteString(fmt.Sprintf(" %d %s,", c, typ))
			}
		}
		s := strings.TrimRight(sb.String(), ",")
		sb.Reset()
		sb.WriteString(s)
		sb.WriteString("\n\n")
	} else {
		sb.WriteString(fmt.Sprintf("Cross-references to 0x%x (%s):\n\n", targetVA, archLabel))
	}

	for _, r := range refs {
		sb.WriteString(r.line)
	}

	if found == 0 {
		sb.WriteString("No references found.\n")
	}
	sb.WriteString(fmt.Sprintf("\n(%d references found)", found))
	if found >= maxRes {
		sb.WriteString(fmt.Sprintf(" -- truncated at max_results=%d", maxRes))
	}

	return sb.String(), nil
}

// --- Binary format openers ---

func xrefOpenPE(path string) (*xrefBinary, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	imageBase := peImageBase(f)
	arch := "x86"
	switch f.FileHeader.Machine {
	case 0x8664:
		arch = "x64"
	case 0xaa64:
		arch = "arm64"
	case 0x01c0, 0x01c2, 0x01c4: // ARM, ARMv7 Thumb, ARMv7
		arch = "arm32"
	}

	var sections []xrefSection
	for _, sec := range f.Sections {
		if sec.Characteristics&0x20000000 == 0 { // IMAGE_SCN_MEM_EXECUTE
			continue
		}
		data, err := sec.Data()
		if err != nil || len(data) == 0 {
			continue
		}
		sections = append(sections, xrefSection{data: data, rva: sec.VirtualAddress})
	}

	return &xrefBinary{imageBase: imageBase, arch: arch, sections: sections, format: "PE"}, nil
}

func xrefOpenELF(path string) (*xrefBinary, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	arch := "x86"
	switch f.Machine {
	case elf.EM_X86_64:
		arch = "x64"
	case elf.EM_386:
		arch = "x86"
	case elf.EM_AARCH64:
		arch = "arm64"
	case elf.EM_ARM:
		arch = "arm32"
	default:
		return nil, fmt.Errorf("unsupported ELF machine: %s", f.Machine)
	}

	// ELF imageBase: lowest PT_LOAD virtual address (usually 0x400000 for x64, 0x0 for PIE)
	var imageBase uint64
	foundLoad := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			if !foundLoad || p.Vaddr < imageBase {
				imageBase = p.Vaddr
				foundLoad = true
			}
		}
	}

	var sections []xrefSection
	for _, sec := range f.Sections {
		if sec.Flags&elf.SHF_EXECINSTR == 0 {
			continue
		}
		data, err := sec.Data()
		if err != nil || len(data) == 0 {
			continue
		}
		// ELF section Addr is absolute VA; convert to RVA relative to imageBase
		if sec.Addr < imageBase {
			continue
		}
		offset := sec.Addr - imageBase
		if offset > 0xFFFFFFFF {
			continue // skip sections beyond 4GB offset from imageBase
		}
		rva := uint32(offset)
		sections = append(sections, xrefSection{data: data, rva: rva})
	}

	return &xrefBinary{imageBase: imageBase, arch: arch, sections: sections, format: "ELF"}, nil
}

func xrefOpenMachO(path string) (*xrefBinary, error) {
	f, err := macho.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return xrefFromMachO(f)
}

func xrefFromMachO(f *macho.File) (*xrefBinary, error) {
	arch := "x86"
	switch f.Cpu {
	case macho.CpuAmd64:
		arch = "x64"
	case macho.Cpu386:
		arch = "x86"
	case macho.CpuArm64:
		arch = "arm64"
	case macho.CpuArm:
		arch = "arm32"
	default:
		return nil, fmt.Errorf("unsupported Mach-O CPU: %s", f.Cpu)
	}

	// Mach-O imageBase: lowest __TEXT segment VA
	var imageBase uint64
	foundText := false
	for _, load := range f.Loads {
		if seg, ok := load.(*macho.Segment); ok {
			if seg.Name == "__TEXT" {
				imageBase = seg.Addr
				foundText = true
				break
			}
		}
	}
	if !foundText {
		// Fallback: use 0 as imageBase
		imageBase = 0
	}

	var sections []xrefSection
	for _, sec := range f.Sections {
		// Mach-O executable sections: __TEXT,__text and similar
		// Check segment name or section attributes
		if sec.Seg != "__TEXT" {
			continue
		}
		data, err := sec.Data()
		if err != nil || len(data) == 0 {
			continue
		}
		if sec.Addr < imageBase {
			continue
		}
		offset := sec.Addr - imageBase
		if offset > 0xFFFFFFFF {
			continue // skip sections beyond 4GB offset from imageBase
		}
		rva := uint32(offset)
		sections = append(sections, xrefSection{data: data, rva: rva})
	}

	return &xrefBinary{imageBase: imageBase, arch: arch, sections: sections, format: "Mach-O"}, nil
}

// --- x86/x64 pattern matchers (unchanged logic) ---

// collectXref64 scans x64 code for references and collects typed results.
func collectXref64(data []byte, secRVA, targetRVA uint32, imageBase uint64, maxRes, found int, refs []xrefResult) ([]xrefResult, int) {
	dataLen := len(data)

	for i := 0; i < dataLen && found < maxRes; i++ {
		instrRVA := secRVA + uint32(i)
		instrVA := imageBase + uint64(instrRVA)

		// E8 rel32 -- CALL relative
		if data[i] == 0xE8 && i+5 <= dataLen {
			rel := int32(binary.LittleEndian.Uint32(data[i+1:]))
			target := int64(instrRVA) + 5 + int64(rel)
			if target >= 0 && target == int64(targetRVA) {
				refs = append(refs, xrefResult{"CALL", fmt.Sprintf("  0x%x: CALL 0x%x  (E8 relative)\n", instrVA, imageBase+uint64(targetRVA))})
				found++
				continue
			}
		}

		// E9 rel32 -- JMP relative
		if data[i] == 0xE9 && i+5 <= dataLen {
			rel := int32(binary.LittleEndian.Uint32(data[i+1:]))
			target := int64(instrRVA) + 5 + int64(rel)
			if target >= 0 && target == int64(targetRVA) {
				refs = append(refs, xrefResult{"JMP", fmt.Sprintf("  0x%x: JMP 0x%x  (E9 relative)\n", instrVA, imageBase+uint64(targetRVA))})
				found++
				continue
			}
		}

		// 0F 80-8F rel32 -- Jcc (conditional jump near)
		if data[i] == 0x0F && i+6 <= dataLen && data[i+1] >= 0x80 && data[i+1] <= 0x8F {
			rel := int32(binary.LittleEndian.Uint32(data[i+2:]))
			target := int64(instrRVA) + 6 + int64(rel)
			if target >= 0 && target == int64(targetRVA) {
				name := jccNames[data[i+1]-0x80]
				refs = append(refs, xrefResult{"Jcc", fmt.Sprintf("  0x%x: %s 0x%x  (0F %02X relative)\n", instrVA, name, imageBase+uint64(targetRVA), data[i+1])})
				found++
				continue
			}
		}

		// REX.W LEA reg, [rip+disp32]
		// REX.W=1 && REX.B=0 required: B=1 changes rm=5 from RIP-relative to r13-base.
		if i+7 <= dataLen {
			rex := data[i]
			if (rex&0x49) == 0x48 && data[i+1] == 0x8D {
				modrm := data[i+2]
				mod := modrm >> 6
				rm := modrm & 0x07
				if mod == 0x00 && rm == 0x05 {
					disp := int32(binary.LittleEndian.Uint32(data[i+3:]))
					target := int64(instrRVA) + 7 + int64(disp)
					if target >= 0 && target == int64(targetRVA) {
						regIdx := ((rex & 0x04) << 1) | ((modrm >> 3) & 0x07)
						refs = append(refs, xrefResult{"LEA", fmt.Sprintf("  0x%x: LEA %s, [0x%x]  (RIP-relative)\n", instrVA, x64RegName(regIdx), imageBase+uint64(targetRVA))})
						found++
						continue
					}
				}
			}
		}

		// FF 15/25 disp32 -- indirect CALL/JMP [rip+disp32]
		if i+6 <= dataLen && data[i] == 0xFF {
			if data[i+1] == 0x15 || data[i+1] == 0x25 {
				disp := int32(binary.LittleEndian.Uint32(data[i+2:]))
				target := int64(instrRVA) + 6 + int64(disp)
				if target >= 0 && target == int64(targetRVA) {
					op := "CALL"
					if data[i+1] == 0x25 {
						op = "JMP"
					}
					refs = append(refs, xrefResult{op, fmt.Sprintf("  0x%x: %s [0x%x]  (indirect RIP-relative)\n", instrVA, op, imageBase+uint64(targetRVA))})
					found++
					continue
				}
			}
		}

		// 68 imm32 -- PUSH (x64: sign-extended to 64-bit)
		// Only matches when targetVA fits in sign-extended int32 range.
		// High-address binaries (imageBase >= 0x80000000) can never match
		// because PUSH imm32 cannot encode addresses above 0x7FFFFFFF.
		if data[i] == 0x68 && i+5 <= dataLen {
			imm := int32(binary.LittleEndian.Uint32(data[i+1:]))
			immVA := uint64(int64(imm))
			targetFullVA := imageBase + uint64(targetRVA)
			if immVA == targetFullVA {
				if i+5 < dataLen && data[i+5] == 0xC3 {
					refs = append(refs, xrefResult{"PUSH", fmt.Sprintf("  0x%x: PUSH 0x%x; RET  (indirect jump via push+ret)\n", instrVA, targetFullVA)})
				} else {
					refs = append(refs, xrefResult{"PUSH", fmt.Sprintf("  0x%x: PUSH 0x%x  (imm32)\n", instrVA, targetFullVA)})
				}
				found++
				continue
			}
		}

		// MOV reg, [rip+disp32] (load) -- REX.W only (64-bit operand).
		// Without REX.W, 8B 05 is MOV eax,[rip+disp32] which still references
		// the same address, but those are less common for pointer-sized data.
		// REX.W=1 && REX.B=0 required: B=1 changes rm=5 from RIP-relative to r13-base.
		// REX.X (bit 1) is irrelevant for non-SIB addressing.
		if i+7 <= dataLen {
			rex := data[i]
			if (rex&0x49) == 0x48 && data[i+1] == 0x8B {
				modrm := data[i+2]
				mod := modrm >> 6
				rm := modrm & 0x07
				if mod == 0x00 && rm == 0x05 {
					disp := int32(binary.LittleEndian.Uint32(data[i+3:]))
					target := int64(instrRVA) + 7 + int64(disp)
					if target >= 0 && target == int64(targetRVA) {
						regIdx := ((rex & 0x04) << 1) | ((modrm >> 3) & 0x07)
						refs = append(refs, xrefResult{"MOV", fmt.Sprintf("  0x%x: MOV %s, [0x%x]  (RIP-relative)\n", instrVA, x64RegName(regIdx), imageBase+uint64(targetRVA))})
						found++
						continue
					}
				}
			}
		}

		// MOV [rip+disp32], reg (store) -- REX.W only, same reasoning as load above.
		if i+7 <= dataLen {
			rex := data[i]
			if (rex&0x49) == 0x48 && data[i+1] == 0x89 {
				modrm := data[i+2]
				mod := modrm >> 6
				rm := modrm & 0x07
				if mod == 0x00 && rm == 0x05 {
					disp := int32(binary.LittleEndian.Uint32(data[i+3:]))
					target := int64(instrRVA) + 7 + int64(disp)
					if target >= 0 && target == int64(targetRVA) {
						regIdx := ((rex & 0x04) << 1) | ((modrm >> 3) & 0x07)
						refs = append(refs, xrefResult{"MOV", fmt.Sprintf("  0x%x: MOV [0x%x], %s  (RIP-relative store)\n", instrVA, imageBase+uint64(targetRVA), x64RegName(regIdx))})
						found++
						continue
					}
				}
			}
		}
	}
	return refs, found
}

// collectXref32 scans x86 32-bit code for references and collects typed results.
// x86 uses absolute addresses for data refs (A1/A3, FF 15/25, PUSH imm32),
// unlike x64 which uses RIP-relative addressing.
func collectXref32(data []byte, secRVA, targetRVA uint32, imageBase uint64, maxRes, found int, refs []xrefResult) ([]xrefResult, int) {
	dataLen := len(data)
	// Safe: x86 PE/ELF ImageBase fits in uint32 (x86 address space is 4GB).
	targetAbsVA := uint32(imageBase) + targetRVA

	for i := 0; i < dataLen && found < maxRes; i++ {
		instrRVA := secRVA + uint32(i)
		instrVA := imageBase + uint64(instrRVA)

		// E8/E9 rel32 -- CALL/JMP relative
		if (data[i] == 0xE8 || data[i] == 0xE9) && i+5 <= dataLen {
			rel := int32(binary.LittleEndian.Uint32(data[i+1:]))
			target := uint32(int64(instrRVA) + 5 + int64(rel))
			if target == targetRVA {
				op := "CALL"
				if data[i] == 0xE9 {
					op = "JMP"
				}
				refs = append(refs, xrefResult{op, fmt.Sprintf("  0x%x: %s 0x%x  (relative)\n", instrVA, op, imageBase+uint64(targetRVA))})
				found++
				continue
			}
		}

		// 0F 80-8F rel32 -- Jcc
		if data[i] == 0x0F && i+6 <= dataLen && data[i+1] >= 0x80 && data[i+1] <= 0x8F {
			rel := int32(binary.LittleEndian.Uint32(data[i+2:]))
			target := uint32(int64(instrRVA) + 6 + int64(rel))
			if target == targetRVA {
				name := jccNames[data[i+1]-0x80]
				refs = append(refs, xrefResult{"Jcc", fmt.Sprintf("  0x%x: %s 0x%x  (relative)\n", instrVA, name, imageBase+uint64(targetRVA))})
				found++
				continue
			}
		}

		// FF 15 [abs32] -- CALL [addr] (indirect, e.g. IAT/GOT)
		// FF 25 [abs32] -- JMP  [addr] (indirect, e.g. IAT thunk/PLT)
		if data[i] == 0xFF && i+6 <= dataLen && (data[i+1] == 0x15 || data[i+1] == 0x25) {
			addr := binary.LittleEndian.Uint32(data[i+2:])
			if addr == targetAbsVA {
				op := "CALL"
				if data[i+1] == 0x25 {
					op = "JMP"
				}
				refs = append(refs, xrefResult{op, fmt.Sprintf("  0x%x: %s [0x%x]  (indirect absolute)\n", instrVA, op, targetAbsVA)})
				found++
				continue
			}
		}

		// A1 [abs32] -- MOV EAX, [addr]
		// A3 [abs32] -- MOV [addr], EAX
		if (data[i] == 0xA1 || data[i] == 0xA3) && i+5 <= dataLen {
			addr := binary.LittleEndian.Uint32(data[i+1:])
			if addr == targetAbsVA {
				op := "MOV EAX, [0x%x]"
				if data[i] == 0xA3 {
					op = "MOV [0x%x], EAX"
				}
				refs = append(refs, xrefResult{"MOV", fmt.Sprintf("  0x%x: "+op+"  (absolute)\n", instrVA, targetAbsVA)})
				found++
				continue
			}
		}

		// 68 imm32 -- PUSH
		if data[i] == 0x68 && i+5 <= dataLen {
			imm := binary.LittleEndian.Uint32(data[i+1:])
			if imm == targetAbsVA {
				if i+5 < dataLen && data[i+5] == 0xC3 {
					refs = append(refs, xrefResult{"PUSH", fmt.Sprintf("  0x%x: PUSH 0x%x; RET  (indirect jump via push+ret)\n", instrVA, targetAbsVA)})
				} else {
					refs = append(refs, xrefResult{"PUSH", fmt.Sprintf("  0x%x: PUSH 0x%x  (absolute)\n", instrVA, targetAbsVA)})
				}
				found++
				continue
			}
		}
	}
	return refs, found
}

// --- ARM64 pattern matcher ---

// collectXrefARM64 scans AArch64 code for references to targetRVA.
// ARM64 instructions are fixed 4 bytes. Key patterns:
//   - BL imm26: direct call (4-byte aligned, +/-128MB range)
//   - B  imm26: direct jump
//   - B.cond imm19: conditional branch
//   - ADRP+ADD/LDR: page-relative data reference (2-instruction pair)
func collectXrefARM64(data []byte, secRVA, targetRVA uint32, imageBase uint64, maxRes, found int, refs []xrefResult) ([]xrefResult, int) {
	targetVA := imageBase + uint64(targetRVA)
	targetPage := targetVA &^ 0xFFF // 4KB page

	for i := 0; i+4 <= len(data) && found < maxRes; i += 4 {
		instrRVA := secRVA + uint32(i)
		instrVA := imageBase + uint64(instrRVA)
		instr := binary.LittleEndian.Uint32(data[i:])

		// BL imm26 -- 1001 01ii iiii iiii iiii iiii iiii iiii
		if instr>>26 == 0x25 {
			imm26 := int32(instr&0x03FFFFFF) << 6 >> 6 // sign-extend 26-bit
			target := instrVA + uint64(int64(imm26)*4)
			if target == targetVA {
				refs = append(refs, xrefResult{"BL", fmt.Sprintf("  0x%x: BL 0x%x\n", instrVA, targetVA)})
				found++
				continue
			}
		}

		// B imm26 -- 0001 01ii iiii iiii iiii iiii iiii iiii
		if instr>>26 == 0x05 {
			imm26 := int32(instr&0x03FFFFFF) << 6 >> 6
			target := instrVA + uint64(int64(imm26)*4)
			if target == targetVA {
				refs = append(refs, xrefResult{"B", fmt.Sprintf("  0x%x: B 0x%x\n", instrVA, targetVA)})
				found++
				continue
			}
		}

		// B.cond imm19 -- 0101 0100 iiii iiii iiii iiii iii0 cccc
		if instr&0xFF000010 == 0x54000000 {
			imm19 := int32((instr>>5)&0x7FFFF) << 13 >> 13
			target := instrVA + uint64(int64(imm19)*4)
			if target == targetVA {
				cond := arm64CondName(instr & 0x0F)
				refs = append(refs, xrefResult{"B", fmt.Sprintf("  0x%x: B.%s 0x%x\n", instrVA, cond, targetVA)})
				found++
				continue
			}
		}

		// ADRP Xd, page -- 1ii1 0000 iiii iiii iiii iiii iiid dddd
		// Followed by ADD Xd, Xd, #offset or LDR Xd, [Xd, #offset]
		if instr&0x9F000000 == 0x90000000 {
			immLo := (instr >> 29) & 0x03
			immHi := int32((instr>>5)&0x7FFFF) << 13 >> 13
			adrpPage := (instrVA &^ 0xFFF) + uint64(int64(immHi)<<14|int64(immLo)<<12)

			if adrpPage == targetPage && i+8 <= len(data) {
				nextInstr := binary.LittleEndian.Uint32(data[i+4:])
				rd := instr & 0x1F

				// ADD Xd, Xn, #imm12 -- 1001 0001 00ii iiii iiii iinn nnnd dddd
				if nextInstr&0xFFC00000 == 0x91000000 {
					nextRd := nextInstr & 0x1F
					nextRn := (nextInstr >> 5) & 0x1F
					if nextRd == rd && nextRn == rd {
						imm12 := (nextInstr >> 10) & 0xFFF
						fullAddr := adrpPage + uint64(imm12)
						if fullAddr == targetVA {
							refs = append(refs, xrefResult{"ADRP", fmt.Sprintf("  0x%x: ADRP+ADD -> 0x%x\n", instrVA, targetVA)})
							found++
							continue
						}
					}
				}

				// LDR Xt, [Xn, #imm12*8] -- 1111 1001 01ii iiii iiii iinn nnnd dddd (64-bit)
				if nextInstr&0xFFC00000 == 0xF9400000 {
					nextRn := (nextInstr >> 5) & 0x1F
					if nextRn == rd {
						imm12 := (nextInstr >> 10) & 0xFFF
						fullAddr := adrpPage + uint64(imm12)*8
						if fullAddr == targetVA {
							refs = append(refs, xrefResult{"ADRP", fmt.Sprintf("  0x%x: ADRP+LDR -> [0x%x]\n", instrVA, targetVA)})
							found++
							continue
						}
					}
				}

				// LDR Wt, [Xn, #imm12*4] -- 1011 1001 01ii iiii iiii iinn nnnd dddd (32-bit)
				if nextInstr&0xFFC00000 == 0xB9400000 {
					nextRn := (nextInstr >> 5) & 0x1F
					if nextRn == rd {
						imm12 := (nextInstr >> 10) & 0xFFF
						fullAddr := adrpPage + uint64(imm12)*4
						if fullAddr == targetVA {
							refs = append(refs, xrefResult{"ADRP", fmt.Sprintf("  0x%x: ADRP+LDR -> [0x%x]\n", instrVA, targetVA)})
							found++
							continue
						}
					}
				}
			}
		}
	}
	return refs, found
}

// --- ARM32 pattern matcher ---

// collectXrefARM32 scans ARM32 code for references to targetRVA.
// ARM32 instructions are fixed 4 bytes. Key patterns:
//   - BL imm24: direct call (+/-32MB range)
//   - B  imm24: direct jump
func collectXrefARM32(data []byte, secRVA, targetRVA uint32, imageBase uint64, maxRes, found int, refs []xrefResult) ([]xrefResult, int) {
	targetVA := imageBase + uint64(targetRVA)

	for i := 0; i+4 <= len(data) && found < maxRes; i += 4 {
		instrRVA := secRVA + uint32(i)
		instrVA := imageBase + uint64(instrRVA)
		instr := binary.LittleEndian.Uint32(data[i:])

		// BL imm24 -- cccc 1011 iiii iiii iiii iiii iiii iiii
		// B  imm24 -- cccc 1010 iiii iiii iiii iiii iiii iiii
		opBits := (instr >> 24) & 0x0F
		if opBits == 0x0B || opBits == 0x0A {
			imm24 := int32(instr&0x00FFFFFF) << 8 >> 8 // sign-extend 24-bit
			// ARM32: PC = instrAddr + 8 (pipeline offset)
			target := instrVA + 8 + uint64(int64(imm24)*4)
			if target == targetVA {
				op := "B"
				if opBits == 0x0B {
					op = "BL"
				}
				refs = append(refs, xrefResult{op, fmt.Sprintf("  0x%x: %s 0x%x\n", instrVA, op, targetVA)})
				found++
				continue
			}
		}
	}
	return refs, found
}

// --- Helpers ---

var jccNames = [16]string{
	"JO", "JNO", "JB", "JNB", "JZ", "JNZ", "JBE", "JNBE",
	"JS", "JNS", "JP", "JNP", "JL", "JNL", "JLE", "JNLE",
}

func x64RegName(idx byte) string {
	names := [16]string{
		"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
	}
	if idx < 16 {
		return names[idx]
	}
	return fmt.Sprintf("r%d", idx)
}

func arm64CondName(cond uint32) string {
	names := [16]string{
		"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
		"hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
	}
	if cond < 16 {
		return names[cond]
	}
	return fmt.Sprintf("cond%d", cond)
}
