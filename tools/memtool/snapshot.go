package memtool

import (
	"fmt"
	"os"
	"sort"
	"sync"
)

// maxSnapshotSize caps the total disk usage per snapshot to 2GB.
const maxSnapshotSize = 2 * 1024 * 1024 * 1024

// memorySnapshot provides disk-backed storage for process memory.
// Used for diff operations.
// Regions are written sequentially; an in-memory index maps virtual addresses to file offsets.
type memorySnapshot struct {
	mu    sync.Mutex
	file  *os.File
	index []snapRegion // sorted by BaseAddress
	total int64        // total bytes written
}

type snapRegion struct {
	BaseAddress uint64
	Size        uint64
	FileOffset  int64
}

func newSnapshot() (*memorySnapshot, error) {
	f, err := os.CreateTemp("", "memtool-snap-*.bin")
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot file: %w", err)
	}
	return &memorySnapshot{file: f}, nil
}

// WriteRegion appends a region's data to the snapshot file.
// Returns error if total snapshot size would exceed maxSnapshotSize (audit H1).
func (s *memorySnapshot) WriteRegion(addr uint64, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.total+int64(len(data)) > maxSnapshotSize {
		return fmt.Errorf("snapshot size limit exceeded (%d GB max)", maxSnapshotSize/(1024*1024*1024))
	}

	offset := s.total
	n, err := s.file.WriteAt(data, offset)
	if err != nil {
		return fmt.Errorf("snapshot write at 0x%X: %w", addr, err)
	}

	s.index = append(s.index, snapRegion{
		BaseAddress: addr,
		Size:        uint64(n),
		FileOffset:  offset,
	})
	s.total += int64(n)
	return nil
}

// ReadAt reads bytes from the snapshot at the given virtual address.
func (s *memorySnapshot) ReadAt(addr uint64, buf []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Binary search for the region containing this address
	idx := sort.Search(len(s.index), func(i int) bool {
		return s.index[i].BaseAddress+s.index[i].Size > addr
	})
	if idx >= len(s.index) {
		return 0, fmt.Errorf("address 0x%X not in snapshot", addr)
	}

	reg := &s.index[idx]
	if addr < reg.BaseAddress || addr >= reg.BaseAddress+reg.Size {
		return 0, fmt.Errorf("address 0x%X not in snapshot", addr)
	}

	inRegionOffset := addr - reg.BaseAddress
	fileOffset := reg.FileOffset + int64(inRegionOffset)

	// Don't read past region boundary
	available := reg.Size - inRegionOffset
	readLen := uint64(len(buf))
	if readLen > available {
		readLen = available
	}

	return s.file.ReadAt(buf[:readLen], fileOffset)
}

// readAtUnlocked reads without locking. Caller must ensure exclusive access
// (e.g., by holding the session mutex). Used by filterFromSnapshot to avoid
// per-chunk lock overhead. (audit L1)
func (s *memorySnapshot) readAtUnlocked(addr uint64, buf []byte) (int, error) {
	idx := sort.Search(len(s.index), func(i int) bool {
		return s.index[i].BaseAddress+s.index[i].Size > addr
	})
	if idx >= len(s.index) {
		return 0, fmt.Errorf("address 0x%X not in snapshot", addr)
	}

	reg := &s.index[idx]
	if addr < reg.BaseAddress || addr >= reg.BaseAddress+reg.Size {
		return 0, fmt.Errorf("address 0x%X not in snapshot", addr)
	}

	inRegionOffset := addr - reg.BaseAddress
	fileOffset := reg.FileOffset + int64(inRegionOffset)

	available := reg.Size - inRegionOffset
	readLen := uint64(len(buf))
	if readLen > available {
		readLen = available
	}

	return s.file.ReadAt(buf[:readLen], fileOffset)
}

// Close removes the snapshot temp file.
func (s *memorySnapshot) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		name := s.file.Name()
		s.file.Close()
		os.Remove(name)
		s.file = nil
	}
	s.index = nil
}

// Size returns the total bytes stored.
func (s *memorySnapshot) Size() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total
}

// takeSnapshot reads all readable regions from the process and writes to disk.
// Reads in chunks to cap memory usage.
func takeSnapshot(reader ProcessReader, protection string) (*memorySnapshot, []MemoryRegion, error) {
	regions, err := reader.Regions()
	if err != nil {
		return nil, nil, err
	}

	snap, err := newSnapshot()
	if err != nil {
		return nil, nil, err
	}

	chunk := make([]byte, scanChunkSize)
	zeros := make([]byte, scanChunkSize) // reused for unreadable parts (audit M3)
	var includedRegions []MemoryRegion

	for _, region := range regions {
		if protection != "" && !matchProtection(region.Protection, protection) {
			continue
		}
		// Skip huge regions (>512MB) to avoid filling disk
		if region.Size > 512*1024*1024 {
			continue
		}

		includedRegions = append(includedRegions, region)

		// Read in chunks and write to snapshot
		for offset := uint64(0); offset < region.Size; offset += scanChunkSize {
			readSize := region.Size - offset
			if readSize > scanChunkSize {
				readSize = scanChunkSize
			}
			buf := chunk[:readSize]
			n, err := reader.ReadMemory(region.BaseAddress+offset, buf)
			if err != nil || n == 0 {
				// Write zeros for unreadable parts to maintain alignment
				if err := snap.WriteRegion(region.BaseAddress+offset, zeros[:readSize]); err != nil {
					snap.Close()
					return nil, nil, err
				}
				continue
			}
			if err := snap.WriteRegion(region.BaseAddress+offset, buf[:n]); err != nil {
				snap.Close()
				return nil, nil, err
			}
		}
	}

	// Sort index for binary search
	sort.Slice(snap.index, func(i, j int) bool {
		return snap.index[i].BaseAddress < snap.index[j].BaseAddress
	})

	return snap, includedRegions, nil
}


