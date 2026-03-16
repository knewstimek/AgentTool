package memtool

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
)

const (
	// Matches stay in memory up to this threshold, then spill to disk.
	// 10M × ~36 bytes (int32) ≈ 360MB — fine for modern systems.
	matchMemThreshold = 10_000_000
	// Absolute maximum matches. Disk-backed, so this is generous.
	// 100M × 12 bytes (int32) = 1.2GB disk, manageable.
	matchAbsoluteMax = 100_000_000
	// Batch size for sequential disk iteration.
	matchDiskBatchSize = 10_000
)

// matchStore provides hybrid in-memory / disk-backed storage for scan matches.
// Under matchMemThreshold, matches live in a slice. Above that, they spill to
// a temp file with fixed-size records: [address uint64 LE][prevData vSize bytes].
// Thread-safety: callers must hold the session mutex.
type matchStore struct {
	mem    []scanMatch // in-memory storage (nil when on disk)
	disk   *os.File    // disk file (nil when in memory)
	count  int
	vSize  int  // value size per match (fixed for the session)
	onDisk bool // true = disk mode
	recSz  int  // record size = 8 + vSize
}

func newMatchStore(vSize int) *matchStore {
	return &matchStore{
		vSize: vSize,
		recSz: 8 + vSize,
	}
}

// promoteCount is the point at which we switch from memory to disk.
// Exported for testing. Uses the module constant by default.
func (ms *matchStore) promoteThreshold() int {
	return matchMemThreshold
}

// Add appends a match. Automatically promotes to disk when threshold is crossed.
func (ms *matchStore) Add(m scanMatch) error {
	if ms.count >= matchAbsoluteMax {
		return nil // silently cap — don't error out mid-scan
	}

	if !ms.onDisk && ms.count >= ms.promoteThreshold() {
		if err := ms.promoteToDisk(); err != nil {
			return err
		}
	}

	if ms.onDisk {
		return ms.appendDisk(m)
	}

	ms.mem = append(ms.mem, m)
	ms.count++
	return nil
}

// AddBulk appends multiple matches efficiently.
func (ms *matchStore) AddBulk(matches []scanMatch) error {
	for i := range matches {
		if err := ms.Add(matches[i]); err != nil {
			return err
		}
	}
	return nil
}

// Count returns the total number of matches.
func (ms *matchStore) Count() int {
	return ms.count
}

// OnDisk returns true if matches are stored on disk.
func (ms *matchStore) OnDisk() bool {
	return ms.onDisk
}

// Get returns the match at index i.
func (ms *matchStore) Get(i int) (scanMatch, error) {
	if i < 0 || i >= ms.count {
		return scanMatch{}, fmt.Errorf("index %d out of range [0,%d)", i, ms.count)
	}
	if !ms.onDisk {
		return ms.mem[i], nil
	}
	return ms.readDisk(i)
}

// GetBatch returns matches from startIdx, up to count items.
func (ms *matchStore) GetBatch(startIdx, count int) ([]scanMatch, error) {
	if startIdx >= ms.count {
		return nil, nil
	}
	if startIdx+count > ms.count {
		count = ms.count - startIdx
	}
	if !ms.onDisk {
		result := make([]scanMatch, count)
		copy(result, ms.mem[startIdx:startIdx+count])
		return result, nil
	}
	return ms.readDiskBatch(startIdx, count)
}

// Iter returns an iterator for efficient sequential access.
// For disk-backed stores, reads in batches to minimize I/O.
func (ms *matchStore) Iter() *matchIter {
	return &matchIter{store: ms}
}

// Close releases resources (temp file if on disk).
func (ms *matchStore) Close() {
	ms.mem = nil
	if ms.disk != nil {
		name := ms.disk.Name()
		ms.disk.Close()
		os.Remove(name)
		ms.disk = nil
	}
	ms.count = 0
}

// --- Disk operations ---

func (ms *matchStore) promoteToDisk() error {
	f, err := os.CreateTemp("", "memtool-matches-*.bin")
	if err != nil {
		return fmt.Errorf("failed to create match store file: %w", err)
	}

	// Write all in-memory matches to disk before changing state.
	// If write fails, clean up temp file and leave memory mode intact. (audit H1)
	buf := make([]byte, ms.recSz)
	for _, m := range ms.mem {
		binary.LittleEndian.PutUint64(buf[:8], m.Address)
		copy(buf[8:], m.PrevData)
		for j := len(m.PrevData); j < ms.vSize; j++ {
			buf[8+j] = 0
		}
		if _, err := f.Write(buf); err != nil {
			name := f.Name()
			f.Close()
			os.Remove(name)
			return fmt.Errorf("match store write failed: %w", err)
		}
	}

	// All writes succeeded — now switch to disk mode
	ms.disk = f
	ms.onDisk = true
	ms.mem = nil
	return nil
}

func (ms *matchStore) appendDisk(m scanMatch) error {
	buf := make([]byte, ms.recSz)
	binary.LittleEndian.PutUint64(buf[:8], m.Address)
	copy(buf[8:], m.PrevData)
	for j := len(m.PrevData); j < ms.vSize; j++ {
		buf[8+j] = 0
	}
	if _, err := ms.disk.Write(buf); err != nil {
		return fmt.Errorf("match store append failed: %w", err)
	}
	ms.count++
	return nil
}

func (ms *matchStore) readDisk(i int) (scanMatch, error) {
	buf := make([]byte, ms.recSz)
	offset := int64(i) * int64(ms.recSz)
	n, err := ms.disk.ReadAt(buf, offset)
	if err != nil || n < ms.recSz {
		return scanMatch{}, fmt.Errorf("match store read at index %d failed: %v", i, err)
	}
	return scanMatch{
		Address:  binary.LittleEndian.Uint64(buf[:8]),
		PrevData: cloneBytes(buf[8 : 8+ms.vSize]),
	}, nil
}

func (ms *matchStore) readDiskBatch(startIdx, count int) ([]scanMatch, error) {
	// Cap batch size to prevent excessive allocation (audit M2)
	const maxBatch = 100_000
	if count > maxBatch {
		count = maxBatch
	}
	buf := make([]byte, count*ms.recSz)
	offset := int64(startIdx) * int64(ms.recSz)
	n, err := ms.disk.ReadAt(buf, offset)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("match store batch read failed: %v", err)
	}
	actual := n / ms.recSz
	result := make([]scanMatch, actual)
	for i := range result {
		off := i * ms.recSz
		result[i] = scanMatch{
			Address:  binary.LittleEndian.Uint64(buf[off : off+8]),
			PrevData: cloneBytes(buf[off+8 : off+8+ms.vSize]),
		}
	}
	return result, nil
}

// --- Iterator ---

// matchIter provides efficient sequential access to match stores.
// For disk-backed stores, it reads in batches of matchDiskBatchSize.
type matchIter struct {
	store   *matchStore
	pos     int          // current position in the store
	batch   []scanMatch  // current batch (disk mode)
	batchOff int         // offset of batch[0] in the store
}

// Next returns the next match, or false if done.
func (it *matchIter) Next() (scanMatch, bool) {
	if it.pos >= it.store.count {
		return scanMatch{}, false
	}

	if !it.store.onDisk {
		m := it.store.mem[it.pos]
		it.pos++
		return m, true
	}

	// Disk: check if we need a new batch
	localIdx := it.pos - it.batchOff
	if it.batch == nil || localIdx >= len(it.batch) {
		remaining := it.store.count - it.pos
		batchSz := matchDiskBatchSize
		if batchSz > remaining {
			batchSz = remaining
		}
		var err error
		it.batch, err = it.store.readDiskBatch(it.pos, batchSz)
		if err != nil || len(it.batch) == 0 {
			return scanMatch{}, false
		}
		it.batchOff = it.pos
		localIdx = 0
	}

	m := it.batch[localIdx]
	it.pos++
	return m, true
}

// --- Parallel merge helper ---

// mergeMatchStores merges multiple in-memory match slices into a single matchStore.
// Used by parallel searchMemory to combine worker results.
func mergeMatchStores(slices [][]scanMatch, vSize int) *matchStore {
	total := 0
	for _, s := range slices {
		total += len(s)
	}

	ms := newMatchStore(vSize)

	// Pre-allocate if fits in memory
	if total <= matchMemThreshold {
		ms.mem = make([]scanMatch, 0, total)
		for _, s := range slices {
			ms.mem = append(ms.mem, s...)
		}
		ms.count = len(ms.mem)
		return ms
	}

	// Large result: will promote to disk during AddBulk.
	// Pre-allocate memory portion first.
	ms.mem = make([]scanMatch, 0, matchMemThreshold)
	for _, s := range slices {
		for i := range s {
			if err := ms.Add(s[i]); err != nil {
				// Disk write failed — return what we have so far (audit H2)
				return ms
			}
		}
	}
	return ms
}

// newMatchStoreFromSlice wraps an existing slice as an in-memory matchStore.
// Takes ownership of the slice (does not copy).
func newMatchStoreFromSlice(matches []scanMatch, vSize int) *matchStore {
	ms := newMatchStore(vSize)
	ms.mem = matches
	ms.count = len(matches)
	return ms
}

// ForEachBatch calls fn with batches of matches for efficient processing.
// batchSize controls how many matches are loaded at once from disk.
// fn receives the batch and the starting index in the store.
func (ms *matchStore) ForEachBatch(batchSize int, fn func(batch []scanMatch, startIdx int) error) error {
	if batchSize <= 0 {
		batchSize = matchDiskBatchSize
	}
	for i := 0; i < ms.count; i += batchSize {
		count := batchSize
		if i+count > ms.count {
			count = ms.count - i
		}
		batch, err := ms.GetBatch(i, count)
		if err != nil {
			return err
		}
		if err := fn(batch, i); err != nil {
			return err
		}
	}
	return nil
}

// sortedMerge is a concurrent-safe helper for collecting matches from parallel workers.
type sortedMerge struct {
	mu      sync.Mutex
	matches []scanMatch
}

func (sm *sortedMerge) append(m []scanMatch) {
	sm.mu.Lock()
	sm.matches = append(sm.matches, m...)
	sm.mu.Unlock()
}
