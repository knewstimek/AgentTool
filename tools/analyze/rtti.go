package analyze

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"strings"
)

// opRTTIDump parses MSVC RTTI (Run-Time Type Information) from a vtable VA.
// Supports both x86 and x64 MSVC RTTI format.
//
// MSVC RTTI layout:
//
//	x86: vtable[-4] -> CompleteObjectLocator (absolute VA pointer)
//	x64: vtable[-8] -> CompleteObjectLocator (absolute VA pointer)
//	Note: the vtable slot is always a full VA pointer. Only the COL's
//	internal fields differ: x86 (signature=0) uses absolute VAs,
//	x64 (signature=1) uses image-base-relative RVAs.
//
// CompleteObjectLocator:
//
//	signature(4) + offset(4) + cdOffset(4) + pTypeDescriptor(4) + pClassHierarchyDescriptor(4)
//	x64 adds: pSelf(4) at offset 20
//
// TypeDescriptor:
//
//	pVFTable(ptr) + spare(ptr) + name(variable, mangled)
//
// ClassHierarchyDescriptor:
//
//	signature(4) + attributes(4) + numBaseClasses(4) + pBaseClassArray(4)
func opRTTIDump(input AnalyzeInput) (string, error) {
	vaStr := input.VA
	if vaStr == "" {
		return "", fmt.Errorf("va is required for rtti_dump (vtable virtual address)")
	}

	vtableVA, err := parseHexAddr(vaStr)
	if err != nil {
		return "", fmt.Errorf("invalid va: %s", vaStr)
	}

	f, err := pe.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("rtti_dump requires a PE file: %w", err)
	}
	defer f.Close()

	imageBase := peImageBase(f)
	is64 := f.FileHeader.Machine == 0x8664 || f.FileHeader.Machine == 0xaa64
	ptrSize := 4
	if is64 {
		ptrSize = 8
	}

	cache := make(secCache)
	return dumpRTTI(f, imageBase, vtableVA, is64, ptrSize, cache)
}

// dumpRTTI extracts RTTI info from a vtable VA. Shared by opRTTIDump and opVtableScan.
func dumpRTTI(f *pe.File, imageBase, vtableVA uint64, is64 bool, ptrSize int, cache secCache) (string, error) {
	if vtableVA < uint64(ptrSize) {
		return "", fmt.Errorf("va 0x%x is too small for RTTI (vtable[-%d] would underflow)", vtableVA, ptrSize)
	}
	colPtrVA := vtableVA - uint64(ptrSize)
	colRef, err := cachedReadValue(f, imageBase, colPtrVA, ptrSize, cache)
	if err != nil {
		return "", fmt.Errorf("no RTTI at this vtable -- vtable[-%d] (0x%x) read failed: %w. Verify this is a valid vtable address", ptrSize, colPtrVA, err)
	}
	if colRef == 0 {
		return "", fmt.Errorf("no RTTI at this vtable -- vtable[-%d] is null", ptrSize)
	}

	colVA := colRef
	if colVA < imageBase {
		return "", fmt.Errorf("no RTTI -- vtable[-%d] = 0x%x (below image base 0x%x, not a valid COL pointer)", ptrSize, colRef, imageBase)
	}

	col, err := readCOL(f, imageBase, colVA, is64, cache)
	if err != nil {
		return "", fmt.Errorf("cannot read CompleteObjectLocator at 0x%x: %w", colVA, err)
	}

	// x64 pSelf cross-validation: COL's own RVA must match pSelf field
	if is64 {
		colRVA := uint32(colVA - imageBase)
		if col.pSelf != colRVA {
			return "", fmt.Errorf("COL pSelf mismatch at 0x%x: pSelf=0x%x, expected RVA=0x%x (corrupt RTTI data)", colVA, col.pSelf, colRVA)
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("RTTI for vtable at 0x%x (%d-bit MSVC):\n\n", vtableVA, ptrSize*8))
	sb.WriteString(fmt.Sprintf("CompleteObjectLocator: 0x%x\n", colVA))
	sb.WriteString(fmt.Sprintf("  signature:  %d\n", col.signature))
	sb.WriteString(fmt.Sprintf("  offset:     %d (this ptr adjustment)\n", col.offset))
	sb.WriteString(fmt.Sprintf("  cdOffset:   %d (constructor displacement)\n", col.cdOffset))

	var tdVA uint64
	if is64 {
		tdVA = imageBase + uint64(col.pTypeDescriptor)
	} else {
		tdVA = uint64(col.pTypeDescriptor)
	}

	typeName, err := readTypeDescriptorName(f, imageBase, tdVA, ptrSize, cache)
	if err != nil {
		sb.WriteString(fmt.Sprintf("  TypeDescriptor: 0x%x (read failed: %s)\n", tdVA, err))
	} else {
		sb.WriteString(fmt.Sprintf("  TypeDescriptor: 0x%x\n", tdVA))
		demangled := demangleMSVC(typeName)
		if demangled != typeName {
			sb.WriteString(fmt.Sprintf("  Class name: %s (%s)\n", demangled, typeName))
		} else {
			sb.WriteString(fmt.Sprintf("  Class name: %s\n", typeName))
		}
	}

	var chdVA uint64
	if is64 {
		chdVA = imageBase + uint64(col.pClassHierarchy)
	} else {
		chdVA = uint64(col.pClassHierarchy)
	}

	bases, err := readClassHierarchy(f, imageBase, chdVA, is64, ptrSize, cache)
	if err != nil {
		sb.WriteString(fmt.Sprintf("\n  ClassHierarchy: 0x%x (read failed: %s)\n", chdVA, err))
	} else if len(bases) > 0 {
		sb.WriteString(fmt.Sprintf("\nBase classes (%d):\n", len(bases)))
		for i, base := range bases {
			demangled := demangleMSVC(base.name)
			if demangled != base.name {
				sb.WriteString(fmt.Sprintf("  [%d] %s (%s) (mdisp=%d, pdisp=%d, vdisp=%d)\n",
					i, demangled, base.name, base.mdisp, base.pdisp, base.vdisp))
			} else {
				sb.WriteString(fmt.Sprintf("  [%d] %s (mdisp=%d, pdisp=%d, vdisp=%d)\n",
					i, base.name, base.mdisp, base.pdisp, base.vdisp))
			}
		}
	}

	return sb.String(), nil
}

// --- Section data cache ---

// secCache caches pe.Section.Data() results to avoid redundant file I/O.
// Keyed by section name. Not thread-safe; intended for single-operation scope.
type secCache map[string][]byte

func cachedSectionData(s *pe.Section, cache secCache) ([]byte, error) {
	if cache != nil {
		if data, ok := cache[s.Name]; ok {
			return data, nil
		}
	}
	data, err := s.Data()
	if err != nil {
		return nil, err
	}
	if cache != nil {
		cache[s.Name] = data
	}
	return data, nil
}

// cachedReadBytes reads 'size' bytes from a PE file at the given VA, using section cache.
func cachedReadBytes(f *pe.File, imageBase, va uint64, size int, cache secCache) ([]byte, error) {
	if va < imageBase {
		return nil, fmt.Errorf("VA 0x%x below image base 0x%x", va, imageBase)
	}
	diff := va - imageBase
	if diff > 0xFFFFFFFF {
		return nil, fmt.Errorf("VA 0x%x too far from image base 0x%x (RVA exceeds 4GB)", va, imageBase)
	}
	rva := uint32(diff)
	fileOff, _, err := rvaToFileOffset(f, rva)
	if err != nil {
		return nil, err
	}

	for _, s := range f.Sections {
		if fileOff >= s.Offset && fileOff < s.Offset+s.Size {
			secData, err := cachedSectionData(s, cache)
			if err != nil {
				return nil, fmt.Errorf("cannot read section: %w", err)
			}
			off := int(fileOff - s.Offset)
			if off+size > len(secData) {
				return nil, fmt.Errorf("need %d bytes at 0x%x but only %d available (section boundary)",
					size, fileOff, len(secData)-off)
			}
			return secData[off : off+size], nil
		}
	}
	return nil, fmt.Errorf("offset 0x%x not in any section", fileOff)
}

// cachedReadValue reads a pointer-sized value from a PE file at the given VA.
func cachedReadValue(f *pe.File, imageBase, va uint64, ptrSize int, cache secCache) (uint64, error) {
	data, err := cachedReadBytes(f, imageBase, va, ptrSize, cache)
	if err != nil {
		return 0, err
	}
	if ptrSize == 8 {
		return binary.LittleEndian.Uint64(data), nil
	}
	return uint64(binary.LittleEndian.Uint32(data)), nil
}

// --- MSVC name demangling ---

// demangleMSVC performs basic MSVC RTTI name demangling.
// Handles class (.?AV), struct (.?AU), and enum (.?AW4) type descriptors.
// E.g. ".?AVbad_exception@std@@" -> "std::bad_exception"
func demangleMSVC(mangled string) string {
	if !strings.HasPrefix(mangled, ".?A") {
		return mangled
	}

	rest := mangled[3:]
	prefix := ""
	switch {
	case strings.HasPrefix(rest, "V"):
		rest = rest[1:] // class -- no prefix
	case strings.HasPrefix(rest, "U"):
		prefix = "struct "
		rest = rest[1:]
	case strings.HasPrefix(rest, "W4"):
		prefix = "enum "
		rest = rest[2:]
	default:
		return mangled
	}

	rest = strings.TrimSuffix(rest, "@@")
	if rest == "" {
		return mangled
	}

	// Split by @ for namespace components, reverse for reading order
	// ".?AVInner@Outer@@" -> ["Inner", "Outer"] -> "Outer::Inner"
	parts := strings.Split(rest, "@")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}

	return prefix + strings.Join(parts, "::")
}

// --- COL / RTTI structures ---

// colData holds parsed CompleteObjectLocator fields.
type colData struct {
	signature       uint32
	offset          uint32
	cdOffset        uint32
	pTypeDescriptor uint32 // RVA for x64, absolute for x86
	pClassHierarchy uint32 // RVA for x64, absolute for x86
	pSelf           uint32 // x64 only: RVA of this COL (for cross-validation)
}

// readCOL reads a CompleteObjectLocator at the given VA.
func readCOL(f *pe.File, imageBase, colVA uint64, is64 bool, cache secCache) (*colData, error) {
	size := 20
	if is64 {
		size = 24
	}
	data, err := cachedReadBytes(f, imageBase, colVA, size, cache)
	if err != nil {
		return nil, err
	}

	col := &colData{
		signature:       binary.LittleEndian.Uint32(data[0:4]),
		offset:          binary.LittleEndian.Uint32(data[4:8]),
		cdOffset:        binary.LittleEndian.Uint32(data[8:12]),
		pTypeDescriptor: binary.LittleEndian.Uint32(data[12:16]),
		pClassHierarchy: binary.LittleEndian.Uint32(data[16:20]),
	}
	if is64 {
		col.pSelf = binary.LittleEndian.Uint32(data[20:24])
	}

	// Validate signature: x86=0, x64=1
	expectedSig := uint32(0)
	if is64 {
		expectedSig = 1
	}
	if col.signature != expectedSig {
		return nil, fmt.Errorf("invalid COL signature %d (expected %d)", col.signature, expectedSig)
	}

	return col, nil
}

// baseClassInfo holds parsed base class information.
type baseClassInfo struct {
	name  string
	mdisp int32 // member displacement
	pdisp int32 // vbtable displacement
	vdisp int32 // displacement within vbtable
}

// readTypeDescriptorName reads the mangled class name from a TypeDescriptor.
func readTypeDescriptorName(f *pe.File, imageBase, tdVA uint64, ptrSize int, cache secCache) (string, error) {
	nameOffset := ptrSize * 2
	maxNameLen := 256
	data, err := cachedReadBytes(f, imageBase, tdVA, nameOffset+maxNameLen, cache)
	if err != nil {
		// Retry with smaller reads for section-boundary cases
		for tryLen := 128; tryLen >= 32; tryLen /= 2 {
			data, err = cachedReadBytes(f, imageBase, tdVA, nameOffset+tryLen, cache)
			if err == nil {
				break
			}
		}
		if err != nil {
			return "", err
		}
	}

	nameData := data[nameOffset:]
	var name string
	for i, b := range nameData {
		if b == 0 {
			name = string(nameData[:i])
			break
		}
	}
	if name == "" && len(nameData) > 0 {
		name = string(nameData)
	}

	return name, nil
}

// readClassHierarchy reads the ClassHierarchyDescriptor and enumerates base classes.
func readClassHierarchy(f *pe.File, imageBase, chdVA uint64, is64 bool, ptrSize int, cache secCache) ([]baseClassInfo, error) {
	data, err := cachedReadBytes(f, imageBase, chdVA, 16, cache)
	if err != nil {
		return nil, err
	}

	numBases := binary.LittleEndian.Uint32(data[8:12])
	if numBases == 0 || numBases > 50 {
		if numBases > 50 {
			return nil, fmt.Errorf("numBaseClasses=%d (likely corrupt data)", numBases)
		}
		return nil, nil
	}

	bcaRef := binary.LittleEndian.Uint32(data[12:16])
	var bcaVA uint64
	if is64 {
		bcaVA = imageBase + uint64(bcaRef)
	} else {
		bcaVA = uint64(bcaRef)
	}

	entrySize := 4
	bcaData, err := cachedReadBytes(f, imageBase, bcaVA, int(numBases)*entrySize, cache)
	if err != nil {
		return nil, fmt.Errorf("cannot read BaseClassArray: %w", err)
	}

	var bases []baseClassInfo
	for i := uint32(0); i < numBases; i++ {
		off := int(i) * entrySize
		bcdRef := binary.LittleEndian.Uint32(bcaData[off : off+4])

		var bcdVA uint64
		if is64 {
			bcdVA = imageBase + uint64(bcdRef)
		} else {
			bcdVA = uint64(bcdRef)
		}

		bcdData, err := cachedReadBytes(f, imageBase, bcdVA, 24, cache)
		if err != nil {
			continue
		}

		tdRef := binary.LittleEndian.Uint32(bcdData[0:4])
		mdisp := int32(binary.LittleEndian.Uint32(bcdData[8:12]))
		pdisp := int32(binary.LittleEndian.Uint32(bcdData[12:16]))
		vdisp := int32(binary.LittleEndian.Uint32(bcdData[16:20]))

		var tdVA uint64
		if is64 {
			tdVA = imageBase + uint64(tdRef)
		} else {
			tdVA = uint64(tdRef)
		}

		name, err := readTypeDescriptorName(f, imageBase, tdVA, ptrSize, cache)
		if err != nil {
			name = fmt.Sprintf("(unreadable @ 0x%x)", tdVA)
		}

		bases = append(bases, baseClassInfo{
			name:  name,
			mdisp: mdisp,
			pdisp: pdisp,
			vdisp: vdisp,
		})
	}

	return bases, nil
}

// readPEBytesAtVA reads 'size' bytes from a PE file at the given VA (uncached).
// Kept for use by other files (followptr, structlayout) that don't need caching.
func readPEBytesAtVA(f *pe.File, imageBase, va uint64, size int) ([]byte, error) {
	return cachedReadBytes(f, imageBase, va, size, nil)
}
