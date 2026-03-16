package memtool

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	pointerScanMaxDepth   = 5
	pointerScanMaxOffset  = 0x1000
	pointerScanMaxResults = 10_000
	pointerScanMaxPerLevel = 500_000 // cap candidates per BFS level
)

// pointerChain represents a chain of pointers leading to the target address.
// Chain: [base] +off1→ [ptr1] +off2→ ... → target
type pointerChain struct {
	BaseAddress uint64
	Offsets     []int64 // offset at each level (can be negative)
}

func (c *pointerChain) String(bo binary.ByteOrder) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[0x%X]", c.BaseAddress))
	for _, off := range c.Offsets {
		if off >= 0 {
			sb.WriteString(fmt.Sprintf(" +0x%X →", off))
		} else {
			sb.WriteString(fmt.Sprintf(" -0x%X →", -off))
		}
	}
	return sb.String()
}

// pointerScan finds pointer chains that lead to the target address.
// Uses BFS from target backwards: find all pointers to target, then find pointers to those, etc.
//
// Algorithm:
// 1. Build a set of valid memory regions for bounds checking
// 2. For each level (starting from target):
//    - Scan all writable memory for pointer values within [target-maxOffset, target+maxOffset]
//    - Each hit becomes a candidate for the next level
// 3. Return chains found
func pointerScan(reader ProcessReader, targetAddr uint64, maxDepth int, maxOffset int, ptrSize int, protection string) ([]pointerChain, error) {
	if maxDepth <= 0 || maxDepth > pointerScanMaxDepth {
		maxDepth = 3
	}
	if maxOffset <= 0 || maxOffset > pointerScanMaxOffset {
		maxOffset = pointerScanMaxOffset
	}
	if ptrSize != 4 && ptrSize != 8 {
		ptrSize = 8
	}

	regions, err := reader.Regions()
	if err != nil {
		return nil, err
	}

	// Build region lookup for bounds checking
	var scanRegions []MemoryRegion
	for _, r := range regions {
		if protection != "" && !matchProtection(r.Protection, protection) {
			continue
		}
		if r.Size > 512*1024*1024 {
			continue
		}
		scanRegions = append(scanRegions, r)
	}

	// BFS: start from target, work backwards
	type candidate struct {
		addr   uint64
		offset int64
	}

	// Level 0: the target itself
	currentTargets := []candidate{{addr: targetAddr, offset: 0}}
	var chains []pointerChain

	// Only scan depth 0 (single-level chains).
	// Multi-level BFS (depth > 0) is O(500K × full memory scan) per level,
	// causing time explosion with no useful output since chains aren't
	// recorded for depth > 0. Limit to single-level. (audit H4/L3)
	for _, target := range currentTargets {
		lowBound := target.addr
		if uint64(maxOffset) <= lowBound {
			lowBound -= uint64(maxOffset)
		} else {
			lowBound = 0
		}
		highBound := target.addr + uint64(maxOffset)

		found := scanForPointers(reader, scanRegions, lowBound, highBound, ptrSize)

		for _, f := range found {
			off := int64(target.addr) - int64(f.pointedValue)
			chains = append(chains, pointerChain{
				BaseAddress: f.sourceAddr,
				Offsets:     []int64{off},
			})
			if len(chains) >= pointerScanMaxResults {
				return chains, nil
			}
		}
	}
	_ = maxDepth // reserved for future multi-level support

	return chains, nil
}

type pointerHit struct {
	sourceAddr   uint64 // address where the pointer was found
	pointedValue uint64 // the pointer value read from memory
}

// scanForPointers scans all regions for pointer-sized values within [low, high].
func scanForPointers(reader ProcessReader, regions []MemoryRegion, low, high uint64, ptrSize int) []pointerHit {
	var hits []pointerHit
	chunk := make([]byte, scanChunkSize)

	for _, region := range regions {
		for offset := uint64(0); offset < region.Size; offset += scanChunkSize {
			readSize := region.Size - offset
			if readSize > scanChunkSize {
				readSize = scanChunkSize
			}

			buf := chunk[:readSize]
			n, err := reader.ReadMemory(region.BaseAddress+offset, buf)
			if err != nil || n < ptrSize {
				continue
			}
			buf = buf[:n]

			// Scan for pointer values aligned to pointer size
			for i := 0; i <= len(buf)-ptrSize; i += ptrSize {
				var val uint64
				if ptrSize == 8 {
					val = binary.LittleEndian.Uint64(buf[i:])
				} else {
					val = uint64(binary.LittleEndian.Uint32(buf[i:]))
				}

				if val >= low && val <= high && val != 0 {
					hits = append(hits, pointerHit{
						sourceAddr:   region.BaseAddress + offset + uint64(i),
						pointedValue: val,
					})
					// Cap hits per scan to prevent unbounded growth
					if len(hits) >= pointerScanMaxPerLevel {
						return hits
					}
				}
			}
		}
	}

	return hits
}
