package analyze

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	defaultXrefMaxResults = 200
	maxXrefMaxResults     = 1000
)

// opXref finds all code locations that reference a target virtual address.
// Scans executable sections for CALL/JMP/LEA/MOV/Jcc patterns (PE files only).
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

	f, err := pe.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("xref requires a PE file: %w", err)
	}
	defer f.Close()

	imageBase := peImageBase(f)
	if targetVA < imageBase {
		return "", fmt.Errorf("target_va 0x%x is below image base 0x%x", targetVA, imageBase)
	}
	if targetVA-imageBase > 0xFFFFFFFF {
		return "", fmt.Errorf("target_va 0x%x is too far from image base 0x%x (RVA exceeds 4GB)", targetVA, imageBase)
	}
	targetRVA := uint32(targetVA - imageBase)

	is64 := f.FileHeader.Machine == 0x8664 || f.FileHeader.Machine == 0xaa64

	maxRes := input.MaxResults
	if maxRes <= 0 {
		maxRes = defaultXrefMaxResults
	}
	if maxRes > maxXrefMaxResults {
		maxRes = maxXrefMaxResults
	}

	// Two-pass: collect results first for summary, then format
	var refs []xrefResult
	found := 0

	for _, sec := range f.Sections {
		// Only scan executable sections
		if sec.Characteristics&0x20000000 == 0 { // IMAGE_SCN_MEM_EXECUTE
			continue
		}
		if found >= maxRes {
			break
		}

		secData, err := sec.Data()
		if err != nil || len(secData) == 0 {
			continue
		}

		if is64 {
			refs, found = collectXref64(secData, sec.VirtualAddress, targetRVA, imageBase, maxRes, found, refs)
		} else {
			refs, found = collectXref32(secData, sec.VirtualAddress, targetRVA, imageBase, maxRes, found, refs)
		}
	}

	var sb strings.Builder

	// Summary statistics
	if found > 0 {
		counts := make(map[string]int)
		for _, r := range refs {
			counts[r.refType]++
		}
		sb.WriteString(fmt.Sprintf("%d references to 0x%x:", found, targetVA))
		for _, typ := range []string{"CALL", "JMP", "LEA", "MOV", "PUSH", "Jcc"} {
			if c, ok := counts[typ]; ok {
				sb.WriteString(fmt.Sprintf(" %d %s,", c, typ))
			}
		}
		// Trim trailing comma and add newline
		s := strings.TrimRight(sb.String(), ",")
		sb.Reset()
		sb.WriteString(s)
		sb.WriteString("\n\n")
	} else {
		sb.WriteString(fmt.Sprintf("Cross-references to 0x%x:\n\n", targetVA))
	}

	// Detail lines
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

// xrefResult holds a single cross-reference result with type classification.
type xrefResult struct {
	refType string // CALL, JMP, LEA, MOV, PUSH, Jcc
	line    string // formatted output line
}

// collectXref64 scans x64 code for references and collects typed results.
func collectXref64(data []byte, secRVA, targetRVA uint32, imageBase uint64, maxRes, found int, refs []xrefResult) ([]xrefResult, int) {
	dataLen := len(data)

	for i := 0; i < dataLen && found < maxRes; i++ {
		instrRVA := secRVA + uint32(i)
		instrVA := imageBase + uint64(instrRVA)

		// E8 rel32 -- CALL relative
		if data[i] == 0xE8 && i+5 <= dataLen {
			rel := int32(binary.LittleEndian.Uint32(data[i+1:]))
			target := uint32(int64(instrRVA) + 5 + int64(rel))
			if target == targetRVA {
				refs = append(refs, xrefResult{"CALL", fmt.Sprintf("  0x%x: CALL 0x%x  (E8 relative)\n", instrVA, imageBase+uint64(targetRVA))})
				found++
				continue
			}
		}

		// E9 rel32 -- JMP relative
		if data[i] == 0xE9 && i+5 <= dataLen {
			rel := int32(binary.LittleEndian.Uint32(data[i+1:]))
			target := uint32(int64(instrRVA) + 5 + int64(rel))
			if target == targetRVA {
				refs = append(refs, xrefResult{"JMP", fmt.Sprintf("  0x%x: JMP 0x%x  (E9 relative)\n", instrVA, imageBase+uint64(targetRVA))})
				found++
				continue
			}
		}

		// 0F 80-8F rel32 -- Jcc (conditional jump near)
		if data[i] == 0x0F && i+6 <= dataLen && data[i+1] >= 0x80 && data[i+1] <= 0x8F {
			rel := int32(binary.LittleEndian.Uint32(data[i+2:]))
			target := uint32(int64(instrRVA) + 6 + int64(rel))
			if target == targetRVA {
				name := jccNames[data[i+1]-0x80]
				refs = append(refs, xrefResult{"Jcc", fmt.Sprintf("  0x%x: %s 0x%x  (0F %02X relative)\n", instrVA, name, imageBase+uint64(targetRVA), data[i+1])})
				found++
				continue
			}
		}

		// REX.W LEA reg, [rip+disp32]
		if i+7 <= dataLen {
			rex := data[i]
			if (rex == 0x48 || rex == 0x4C) && data[i+1] == 0x8D {
				modrm := data[i+2]
				mod := modrm >> 6
				rm := modrm & 0x07
				if mod == 0x00 && rm == 0x05 {
					disp := int32(binary.LittleEndian.Uint32(data[i+3:]))
					target := uint32(int64(instrRVA) + 7 + int64(disp))
					if target == targetRVA {
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
				target := uint32(int64(instrRVA) + 6 + int64(disp))
				if target == targetRVA {
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
			targetVA := imageBase + uint64(targetRVA)
			if immVA == targetVA {
				if i+5 < dataLen && data[i+5] == 0xC3 {
					refs = append(refs, xrefResult{"PUSH", fmt.Sprintf("  0x%x: PUSH 0x%x; RET  (indirect jump via push+ret)\n", instrVA, targetVA)})
				} else {
					refs = append(refs, xrefResult{"PUSH", fmt.Sprintf("  0x%x: PUSH 0x%x  (imm32)\n", instrVA, targetVA)})
				}
				found++
				continue
			}
		}

		// MOV reg, [rip+disp32] (load) -- REX.W only (64-bit operand).
		// Without REX.W, 8B 05 is MOV eax,[rip+disp32] which still references
		// the same address, but those are less common for pointer-sized data.
		if i+7 <= dataLen {
			rex := data[i]
			if (rex == 0x48 || rex == 0x4C) && data[i+1] == 0x8B {
				modrm := data[i+2]
				mod := modrm >> 6
				rm := modrm & 0x07
				if mod == 0x00 && rm == 0x05 {
					disp := int32(binary.LittleEndian.Uint32(data[i+3:]))
					target := uint32(int64(instrRVA) + 7 + int64(disp))
					if target == targetRVA {
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
			if (rex == 0x48 || rex == 0x4C) && data[i+1] == 0x89 {
				modrm := data[i+2]
				mod := modrm >> 6
				rm := modrm & 0x07
				if mod == 0x00 && rm == 0x05 {
					disp := int32(binary.LittleEndian.Uint32(data[i+3:]))
					target := uint32(int64(instrRVA) + 7 + int64(disp))
					if target == targetRVA {
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
	// Safe: x86 PE ImageBase field is uint32, so uint32(imageBase) is lossless.
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

		// FF 15 [abs32] -- CALL [addr] (indirect, e.g. IAT)
		// FF 25 [abs32] -- JMP  [addr] (indirect, e.g. IAT thunk)
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

// scanXref64 scans x64 code for references to targetRVA using RIP-relative addressing.
// Deprecated: use collectXref64 instead. Kept for backward compatibility.
func scanXref64(data []byte, secRVA, targetRVA uint32, imageBase uint64, maxRes, found int, sb *strings.Builder) int {
	dataLen := len(data)

	for i := 0; i < dataLen && found < maxRes; i++ {
		instrRVA := secRVA + uint32(i)
		instrVA := imageBase + uint64(instrRVA)

		// E8 rel32 -- CALL relative
		if data[i] == 0xE8 && i+5 <= dataLen {
			rel := int32(binary.LittleEndian.Uint32(data[i+1:]))
			target := uint32(int64(instrRVA) + 5 + int64(rel))
			if target == targetRVA {
				fmt.Fprintf(sb, "  0x%x: CALL 0x%x  (E8 relative)\n", instrVA, imageBase+uint64(targetRVA))
				found++
				continue
			}
		}

		// E9 rel32 -- JMP relative
		if data[i] == 0xE9 && i+5 <= dataLen {
			rel := int32(binary.LittleEndian.Uint32(data[i+1:]))
			target := uint32(int64(instrRVA) + 5 + int64(rel))
			if target == targetRVA {
				fmt.Fprintf(sb, "  0x%x: JMP 0x%x  (E9 relative)\n", instrVA, imageBase+uint64(targetRVA))
				found++
				continue
			}
		}

		// 0F 80-8F rel32 -- Jcc (conditional jump near)
		if data[i] == 0x0F && i+6 <= dataLen && data[i+1] >= 0x80 && data[i+1] <= 0x8F {
			rel := int32(binary.LittleEndian.Uint32(data[i+2:]))
			target := uint32(int64(instrRVA) + 6 + int64(rel))
			if target == targetRVA {
				name := jccNames[data[i+1]-0x80]
				fmt.Fprintf(sb, "  0x%x: %s 0x%x  (0F %02X relative)\n", instrVA, name, imageBase+uint64(targetRVA), data[i+1])
				found++
				continue
			}
		}

		// REX.W LEA reg, [rip+disp32]: 48/4C 8D modrm(00,reg,101) disp32
		// instrLen = 7, target = instrRVA + 7 + disp32
		if i+7 <= dataLen {
			rex := data[i]
			if (rex == 0x48 || rex == 0x4C) && data[i+1] == 0x8D {
				modrm := data[i+2]
				mod := modrm >> 6
				rm := modrm & 0x07
				if mod == 0x00 && rm == 0x05 { // [rip+disp32]
					disp := int32(binary.LittleEndian.Uint32(data[i+3:]))
					target := uint32(int64(instrRVA) + 7 + int64(disp))
					if target == targetRVA {
						regIdx := ((rex & 0x04) << 1) | ((modrm >> 3) & 0x07)
						fmt.Fprintf(sb, "  0x%x: LEA %s, [0x%x]  (RIP-relative)\n", instrVA, x64RegName(regIdx), imageBase+uint64(targetRVA))
						found++
						continue
					}
				}
			}
		}

		// FF 15 disp32 -- CALL [rip+disp32] (indirect call, e.g. IAT)
		// FF 25 disp32 -- JMP  [rip+disp32] (indirect jump)
		if i+6 <= dataLen && data[i] == 0xFF {
			if data[i+1] == 0x15 || data[i+1] == 0x25 {
				disp := int32(binary.LittleEndian.Uint32(data[i+2:]))
				target := uint32(int64(instrRVA) + 6 + int64(disp))
				if target == targetRVA {
					op := "CALL"
					if data[i+1] == 0x25 {
						op = "JMP"
					}
					fmt.Fprintf(sb, "  0x%x: %s [0x%x]  (indirect RIP-relative)\n", instrVA, op, imageBase+uint64(targetRVA))
					found++
					continue
				}
			}
		}

		// 68 imm32 [C3] -- PUSH imm32 (sign-extended to 64-bit)
		// Catches push+ret indirect jump pattern; also plain PUSH data ref
		// Only matches when target VA fits in sign-extended int32
		if data[i] == 0x68 && i+5 <= dataLen {
			imm := int32(binary.LittleEndian.Uint32(data[i+1:]))
			// In x64, push imm32 sign-extends to 64-bit
			immVA := uint64(int64(imm))
			targetVA := imageBase + uint64(targetRVA)
			if immVA == targetVA {
				if i+5 < dataLen && data[i+5] == 0xC3 {
					fmt.Fprintf(sb, "  0x%x: PUSH 0x%x; RET  (indirect jump via push+ret)\n", instrVA, targetVA)
				} else {
					fmt.Fprintf(sb, "  0x%x: PUSH 0x%x  (imm32)\n", instrVA, targetVA)
				}
				found++
				continue
			}
		}

		// MOV reg, [rip+disp32]: 48/4C 8B modrm(00,reg,101) disp32 (load)
		if i+7 <= dataLen {
			rex := data[i]
			if (rex == 0x48 || rex == 0x4C) && data[i+1] == 0x8B {
				modrm := data[i+2]
				mod := modrm >> 6
				rm := modrm & 0x07
				if mod == 0x00 && rm == 0x05 {
					disp := int32(binary.LittleEndian.Uint32(data[i+3:]))
					target := uint32(int64(instrRVA) + 7 + int64(disp))
					if target == targetRVA {
						regIdx := ((rex & 0x04) << 1) | ((modrm >> 3) & 0x07)
						fmt.Fprintf(sb, "  0x%x: MOV %s, [0x%x]  (RIP-relative)\n", instrVA, x64RegName(regIdx), imageBase+uint64(targetRVA))
						found++
						continue
					}
				}
			}
		}

		// MOV [rip+disp32], reg: 48/4C 89 modrm(00,reg,101) disp32 (store)
		if i+7 <= dataLen {
			rex := data[i]
			if (rex == 0x48 || rex == 0x4C) && data[i+1] == 0x89 {
				modrm := data[i+2]
				mod := modrm >> 6
				rm := modrm & 0x07
				if mod == 0x00 && rm == 0x05 {
					disp := int32(binary.LittleEndian.Uint32(data[i+3:]))
					target := uint32(int64(instrRVA) + 7 + int64(disp))
					if target == targetRVA {
						regIdx := ((rex & 0x04) << 1) | ((modrm >> 3) & 0x07)
						fmt.Fprintf(sb, "  0x%x: MOV [0x%x], %s  (RIP-relative store)\n", instrVA, imageBase+uint64(targetRVA), x64RegName(regIdx))
						found++
						continue
					}
				}
			}
		}
	}
	return found
}

// scanXref32 scans x86 32-bit code for references to targetRVA.
// scanXref32 is the legacy string-builder variant of collectXref32.
// Deprecated: use collectXref32 (returns typed results for summary stats).
func scanXref32(data []byte, secRVA, targetRVA uint32, imageBase uint64, maxRes, found int, sb *strings.Builder) int {
	dataLen := len(data)
	// Safe: x86 PE ImageBase field is uint32, so uint32(imageBase) is lossless.
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
				fmt.Fprintf(sb, "  0x%x: %s 0x%x  (relative)\n", instrVA, op, imageBase+uint64(targetRVA))
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
				fmt.Fprintf(sb, "  0x%x: %s 0x%x  (relative)\n", instrVA, name, imageBase+uint64(targetRVA))
				found++
				continue
			}
		}

		// FF 15 [abs32] -- CALL [addr] (indirect, e.g. IAT)
		// FF 25 [abs32] -- JMP  [addr] (indirect, e.g. IAT thunk)
		if data[i] == 0xFF && i+6 <= dataLen && (data[i+1] == 0x15 || data[i+1] == 0x25) {
			addr := binary.LittleEndian.Uint32(data[i+2:])
			if addr == targetAbsVA {
				op := "CALL"
				if data[i+1] == 0x25 {
					op = "JMP"
				}
				fmt.Fprintf(sb, "  0x%x: %s [0x%x]  (indirect absolute)\n", instrVA, op, targetAbsVA)
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
				fmt.Fprintf(sb, "  0x%x: "+op+"  (absolute)\n", instrVA, targetAbsVA)
				found++
				continue
			}
		}

		// 68 imm32 -- PUSH absolute address (common for 32-bit data refs)
		// If followed by C3 (RET), this is an indirect jump via push+ret
		if data[i] == 0x68 && i+5 <= dataLen {
			imm := binary.LittleEndian.Uint32(data[i+1:])
			if imm == targetAbsVA {
				if i+5 < dataLen && data[i+5] == 0xC3 {
					fmt.Fprintf(sb, "  0x%x: PUSH 0x%x; RET  (indirect jump via push+ret)\n", instrVA, targetAbsVA)
				} else {
					fmt.Fprintf(sb, "  0x%x: PUSH 0x%x  (absolute)\n", instrVA, targetAbsVA)
				}
				found++
				continue
			}
		}
	}
	return found
}

// jccNames maps Jcc second-byte (0x80-0x8F) to mnemonic.
var jccNames = [16]string{
	"JO", "JNO", "JB", "JNB", "JZ", "JNZ", "JBE", "JNBE",
	"JS", "JNS", "JP", "JNP", "JL", "JNL", "JLE", "JNLE",
}

// x64RegName returns the x64 64-bit register name for encoding index 0-15.
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
