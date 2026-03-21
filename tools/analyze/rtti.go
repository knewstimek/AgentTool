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
//   x86: vtable[-4] -> CompleteObjectLocator (absolute pointer)
//   x64: vtable[-8] -> CompleteObjectLocator (RVA-based, relative to image base)
//
// CompleteObjectLocator:
//   signature(4) + offset(4) + cdOffset(4) + pTypeDescriptor(4) + pClassHierarchyDescriptor(4)
//   x64 adds: pSelf(4) at offset 20
//
// TypeDescriptor:
//   pVFTable(ptr) + spare(ptr) + name(variable, mangled)
//
// ClassHierarchyDescriptor:
//   signature(4) + attributes(4) + numBaseClasses(4) + pBaseClassArray(4)
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

	// Read vtable[-ptrSize] to get COL pointer/RVA
	// x64: COL reference is a 32-bit RVA stored in a pointer-sized slot
	// x86: COL reference is a 32-bit absolute VA
	// Both cases: read 4 bytes (the significant part of the slot)
	if vtableVA < uint64(ptrSize) {
		return "", fmt.Errorf("va 0x%x is too small for RTTI (vtable[-%d] would underflow)", vtableVA, ptrSize)
	}
	colPtrVA := vtableVA - uint64(ptrSize)
	colRef, err := readPEValueAtVA(f, imageBase, colPtrVA, 4)
	if err != nil {
		return "", fmt.Errorf("no RTTI at this vtable -- vtable[-%d] (0x%x) read failed: %w. Verify this is a valid vtable address", ptrSize, colPtrVA, err)
	}
	if colRef == 0 {
		return "", fmt.Errorf("no RTTI at this vtable -- vtable[-%d] is null", ptrSize)
	}

	// Resolve COL address
	var colVA uint64
	if is64 {
		// x64: colRef is an RVA (32-bit), resolve relative to image base
		colVA = imageBase + colRef
	} else {
		// x86: colRef is an absolute VA -- must be >= imageBase
		if colRef < imageBase {
			return "", fmt.Errorf("no RTTI -- vtable[-%d] = 0x%x (below image base 0x%x, not a valid VA)", ptrSize, colRef, imageBase)
		}
		colVA = colRef
	}

	// Read CompleteObjectLocator
	col, err := readCOL(f, imageBase, colVA, is64)
	if err != nil {
		return "", fmt.Errorf("cannot read CompleteObjectLocator at 0x%x: %w", colVA, err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("RTTI for vtable at 0x%x (%d-bit MSVC):\n\n", vtableVA, ptrSize*8))
	sb.WriteString(fmt.Sprintf("CompleteObjectLocator: 0x%x\n", colVA))
	sb.WriteString(fmt.Sprintf("  signature:  %d\n", col.signature))
	sb.WriteString(fmt.Sprintf("  offset:     %d (this ptr adjustment)\n", col.offset))
	sb.WriteString(fmt.Sprintf("  cdOffset:   %d (constructor displacement)\n", col.cdOffset))

	// Read TypeDescriptor
	var tdVA uint64
	if is64 {
		tdVA = imageBase + uint64(col.pTypeDescriptor)
	} else {
		tdVA = uint64(col.pTypeDescriptor)
	}

	typeName, err := readTypeDescriptorName(f, imageBase, tdVA, ptrSize)
	if err != nil {
		sb.WriteString(fmt.Sprintf("  TypeDescriptor: 0x%x (read failed: %s)\n", tdVA, err))
	} else {
		sb.WriteString(fmt.Sprintf("  TypeDescriptor: 0x%x\n", tdVA))
		sb.WriteString(fmt.Sprintf("  Class name: %s\n", typeName))
	}

	// Read ClassHierarchyDescriptor
	var chdVA uint64
	if is64 {
		chdVA = imageBase + uint64(col.pClassHierarchy)
	} else {
		chdVA = uint64(col.pClassHierarchy)
	}

	bases, err := readClassHierarchy(f, imageBase, chdVA, is64, ptrSize)
	if err != nil {
		sb.WriteString(fmt.Sprintf("\n  ClassHierarchy: 0x%x (read failed: %s)\n", chdVA, err))
	} else if len(bases) > 0 {
		sb.WriteString(fmt.Sprintf("\nBase classes (%d):\n", len(bases)))
		for i, base := range bases {
			sb.WriteString(fmt.Sprintf("  [%d] %s (mdisp=%d, pdisp=%d, vdisp=%d)\n",
				i, base.name, base.mdisp, base.pdisp, base.vdisp))
		}
	}

	return sb.String(), nil
}

// colData holds parsed CompleteObjectLocator fields.
type colData struct {
	signature       uint32
	offset          uint32
	cdOffset        uint32
	pTypeDescriptor uint32 // RVA for x64, absolute for x86
	pClassHierarchy uint32 // RVA for x64, absolute for x86
}

// readCOL reads a CompleteObjectLocator at the given VA.
func readCOL(f *pe.File, imageBase, colVA uint64, is64 bool) (*colData, error) {
	// COL is 20 bytes (x86) or 24 bytes (x64, extra pSelf field)
	size := 20
	if is64 {
		size = 24
	}
	data, err := readPEBytesAtVA(f, imageBase, colVA, size)
	if err != nil {
		return nil, err
	}

	return &colData{
		signature:       binary.LittleEndian.Uint32(data[0:4]),
		offset:          binary.LittleEndian.Uint32(data[4:8]),
		cdOffset:        binary.LittleEndian.Uint32(data[8:12]),
		pTypeDescriptor: binary.LittleEndian.Uint32(data[12:16]),
		pClassHierarchy: binary.LittleEndian.Uint32(data[16:20]),
	}, nil
}

// readTypeDescriptorName reads the mangled class name from a TypeDescriptor.
// TypeDescriptor layout: pVFTable(ptr) + spare(ptr) + name(char[])
func readTypeDescriptorName(f *pe.File, imageBase, tdVA uint64, ptrSize int) (string, error) {
	// Skip pVFTable + spare to get to name offset
	nameOffset := ptrSize * 2
	// Read enough bytes for the name (mangled names are usually < 256 chars)
	maxNameLen := 256
	data, err := readPEBytesAtVA(f, imageBase, tdVA, nameOffset+maxNameLen)
	if err != nil {
		return "", err
	}

	// Extract null-terminated string
	nameData := data[nameOffset:]
	var name string
	for i, b := range nameData {
		if b == 0 {
			name = string(nameData[:i])
			break
		}
	}
	if name == "" && len(nameData) > 0 {
		name = string(nameData) // truncated, no null found
	}

	return name, nil
}

// baseClassInfo holds parsed base class information.
type baseClassInfo struct {
	name  string
	mdisp int32 // member displacement
	pdisp int32 // vbtable displacement
	vdisp int32 // displacement within vbtable
}

// readClassHierarchy reads the ClassHierarchyDescriptor and enumerates base classes.
func readClassHierarchy(f *pe.File, imageBase, chdVA uint64, is64 bool, ptrSize int) ([]baseClassInfo, error) {
	// ClassHierarchyDescriptor: signature(4) + attributes(4) + numBaseClasses(4) + pBaseClassArray(4)
	data, err := readPEBytesAtVA(f, imageBase, chdVA, 16)
	if err != nil {
		return nil, err
	}

	numBases := binary.LittleEndian.Uint32(data[8:12])
	if numBases == 0 || numBases > 50 {
		// Sanity: real C++ hierarchies rarely exceed 50 base classes
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

	// BaseClassArray is an array of pointers/RVAs to BaseClassDescriptors
	entrySize := 4 // RVA for x64, pointer for x86
	bcaData, err := readPEBytesAtVA(f, imageBase, bcaVA, int(numBases)*entrySize)
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

		// BaseClassDescriptor: pTypeDescriptor(4) + numContainedBases(4) + mdisp(4) + pdisp(4) + vdisp(4) + attributes(4)
		bcdData, err := readPEBytesAtVA(f, imageBase, bcdVA, 24)
		if err != nil {
			continue // skip unreadable entries
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

		name, err := readTypeDescriptorName(f, imageBase, tdVA, ptrSize)
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

// readPEBytesAtVA reads 'size' bytes from a PE file at the given VA.
func readPEBytesAtVA(f *pe.File, imageBase, va uint64, size int) ([]byte, error) {
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
			secData, err := s.Data()
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
