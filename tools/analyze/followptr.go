package analyze

import (
	"debug/pe"
	"fmt"
	"strings"
)

const (
	defaultFollowPtrCount = 4
	maxFollowPtrCount     = 10
)

// opFollowPtr follows a chain of pointers in a PE file starting from a VA.
// At each step, reads a pointer-sized value at the current VA, resolves it
// as the next VA, and annotates with symbol/section info. Stops on null,
// unmapped address, or reaching the depth limit.
func opFollowPtr(input AnalyzeInput) (string, error) {
	vaStr := input.VA
	if vaStr == "" {
		return "", fmt.Errorf("va is required for follow_ptr (starting virtual address)")
	}

	startVA, err := parseHexAddr(vaStr)
	if err != nil {
		return "", fmt.Errorf("invalid va: %s", vaStr)
	}

	count := input.Count
	if count <= 0 {
		count = defaultFollowPtrCount
	}
	if count > maxFollowPtrCount {
		count = maxFollowPtrCount
	}

	f, err := pe.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("follow_ptr requires a PE file: %w", err)
	}
	defer f.Close()

	imageBase := peImageBase(f)
	is64 := f.FileHeader.Machine == 0x8664 || f.FileHeader.Machine == 0xaa64
	ptrSize := 4
	if is64 {
		ptrSize = 8
	}

	// Validate starting VA is within PE address space
	if startVA < imageBase {
		return "", fmt.Errorf("va 0x%x is below image base 0x%x", startVA, imageBase)
	}

	symbols := peSymbolMap(f, imageBase)
	cache := make(secCache)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Pointer chain from 0x%x (%d-bit):\n\n", startVA, ptrSize*8))

	currentVA := startVA
	visited := make(map[uint64]bool, count)
	for i := 0; i < count; i++ {
		if visited[currentVA] {
			sb.WriteString(fmt.Sprintf("[%d] 0x%x -> (circular reference -- already visited)\n", i, currentVA))
			break
		}
		visited[currentVA] = true
		// Read pointer at currentVA
		val, err := cachedReadValue(f, imageBase, currentVA, ptrSize, cache)
		if err != nil {
			sb.WriteString(fmt.Sprintf("[%d] 0x%x -> (read failed: %s)\n", i, currentVA, err))
			break
		}

		// Annotate current VA
		annotation := annotateVA(f, imageBase, currentVA, symbols)
		nextAnnotation := annotateVA(f, imageBase, val, symbols)

		sb.WriteString(fmt.Sprintf("[%d] 0x%x%s -> 0x%x%s\n",
			i, currentVA, annotation, val, nextAnnotation))

		if val == 0 {
			sb.WriteString("    (null pointer -- chain ends)\n")
			break
		}

		// Check if next VA is mappable
		if val < imageBase {
			sb.WriteString(fmt.Sprintf("    (0x%x below image base 0x%x -- chain ends)\n", val, imageBase))
			break
		}
		if val-imageBase > 0xFFFFFFFF {
			sb.WriteString(fmt.Sprintf("    (0x%x RVA exceeds 4GB -- chain ends)\n", val))
			break
		}
		rva := uint32(val - imageBase)
		if _, _, err := rvaToFileOffset(f, rva); err != nil {
			sb.WriteString(fmt.Sprintf("    (0x%x not mapped to any section -- chain ends)\n", val))
			break
		}

		currentVA = val
	}

	return sb.String(), nil
}

// annotateVA returns a short annotation for a VA: symbol name, section name, or empty.
func annotateVA(f *pe.File, imageBase, va uint64, symbols map[uint64]string) string {
	if va == 0 {
		return ""
	}
	if name, ok := symbols[va]; ok {
		return fmt.Sprintf(" (%s)", name)
	}
	if va >= imageBase && va-imageBase <= 0xFFFFFFFF {
		rva := uint32(va - imageBase)
		if sec := sectionNameForRVA(f, rva); sec != "" {
			return fmt.Sprintf(" (%s)", sec)
		}
	}
	return ""
}
