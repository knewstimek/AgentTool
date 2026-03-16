package memtool

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
)

const scanChunkSize = 4 * 1024 * 1024 // 4MB chunks to cap memory usage

// searchMemory performs initial scan across all readable regions.
// Uses parallel goroutines (one per CPU core) for throughput.
// Returns a hybrid matchStore that auto-promotes to disk for large result sets.
func searchMemory(reader ProcessReader, pattern []byte, vt ValueType, vSize int, protection string) (*matchStore, error) {
	regions, err := reader.Regions()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate regions: %w", err)
	}

	// Filter regions
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

	if len(scanRegions) == 0 {
		return newMatchStore(vSize), nil
	}

	// Determine worker count
	numWorkers := runtime.NumCPU()
	if numWorkers > 8 {
		numWorkers = 8
	}
	if numWorkers > len(scanRegions) {
		numWorkers = len(scanRegions)
	}

	// Each worker collects matches locally, then we merge
	type workerResult struct {
		matches []scanMatch
	}
	results := make([]workerResult, numWorkers)
	regionChan := make(chan MemoryRegion, len(scanRegions))
	for _, r := range scanRegions {
		regionChan <- r
	}
	close(regionChan)

	patLen := len(pattern)
	stepSize := valueSize(vt)
	if stepSize == 0 {
		stepSize = 1
	}

	// Shared atomic counter to enforce global limit (audit H3 — data race fix)
	var globalCount int64
	limitReached := func() bool { return atomic.LoadInt64(&globalCount) >= int64(matchAbsoluteMax) }

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var local []scanMatch
			chunk := make([]byte, scanChunkSize+patLen)
			var overlap []byte

			for region := range regionChan {
				if limitReached() {
					break
				}
				overlap = overlap[:0]

				for offset := uint64(0); offset < region.Size; offset += scanChunkSize {
					if limitReached() {
						break
					}

					readSize := region.Size - offset
					if readSize > scanChunkSize {
						readSize = scanChunkSize
					}

					buf := chunk[:len(overlap)+int(readSize)]
					copy(buf, overlap)

					n, err := reader.ReadMemory(region.BaseAddress+offset, buf[len(overlap):])
					if err != nil || n == 0 {
						overlap = overlap[:0]
						continue
					}
					buf = buf[:len(overlap)+n]

					searchEnd := len(buf) - patLen
					for i := 0; i <= searchEnd; i++ {
						if bytes.Equal(buf[i:i+patLen], pattern) {
							addr := region.BaseAddress + offset - uint64(len(overlap)) + uint64(i)
							local = append(local, scanMatch{
								Address:  addr,
								PrevData: cloneBytes(buf[i : i+patLen]),
							})
							atomic.AddInt64(&globalCount, 1)
							if limitReached() {
								goto done
							}
							if stepSize > 1 {
								i += stepSize - 1
							}
						}
					}

					if len(buf) >= patLen-1 {
						overlap = cloneBytes(buf[len(buf)-patLen+1:])
					} else {
						overlap = overlap[:0]
					}
				}
			}
		done:
			results[idx] = workerResult{matches: local}
		}(w)
	}
	wg.Wait()

	// Collect all worker results into sorted slice
	totalLen := 0
	for _, r := range results {
		totalLen += len(r.matches)
	}

	all := make([]scanMatch, 0, totalLen)
	for _, r := range results {
		all = append(all, r.matches...)
	}

	// Sort by address for batch-read optimization in filterMatches
	sort.Slice(all, func(i, j int) bool {
		return all[i].Address < all[j].Address
	})

	// Build hybrid matchStore (auto-promotes to disk if > threshold)
	store := newMatchStore(vSize)
	if len(all) <= matchMemThreshold {
		// Fast path: take ownership of the sorted slice
		store.mem = all
		store.count = len(all)
	} else {
		// Will spill to disk during AddBulk
		store.mem = make([]scanMatch, 0, matchMemThreshold)
		if err := store.AddBulk(all); err != nil {
			store.Close()
			return nil, fmt.Errorf("failed to store matches: %w", err)
		}
	}

	return store, nil
}

// filterBatchSize is the max gap between addresses to batch into a single read.
// Matches within this distance are read in one ReadProcessMemory call.
const filterBatchSize = 64 * 1024 // 64KB

// filterMatches re-reads current values and applies a filter condition.
// Uses batched reads: groups adjacent matches (within 64KB) into single
// ReadProcessMemory calls to minimize syscall overhead.
// Works with both in-memory and disk-backed matchStores via iterator.
func filterMatches(reader ProcessReader, session *scanSession, filterType string, newValue []byte) (*matchStore, error) {
	if reader == nil {
		return nil, fmt.Errorf("process reader is closed")
	}
	vSize := session.valueSize
	if vSize == 0 {
		return nil, fmt.Errorf("cannot filter: unknown value size")
	}

	store := session.store
	if store == nil || store.Count() == 0 {
		return newMatchStore(vSize), nil
	}

	result := newMatchStore(vSize)

	// Process matches in batches for both memory and disk stores.
	// We iterate in chunks and group adjacent addresses for batched reads.
	const iterBatch = 10_000

	var pending []scanMatch // current group of matches pending read

	flushPending := func() error {
		if len(pending) == 0 {
			return nil
		}

		// Group pending into read batches by address proximity
		i := 0
		for i < len(pending) {
			batchStart := pending[i].Address
			j := i + 1
			for j < len(pending) {
				gap := pending[j].Address + uint64(vSize) - batchStart
				if gap > filterBatchSize {
					break
				}
				j++
			}

			// Read [batchStart, lastAddr+vSize) in one call
			batchEnd := pending[j-1].Address + uint64(vSize)
			rangeSize := int(batchEnd - batchStart)
			buf := make([]byte, rangeSize)
			n, err := reader.ReadMemory(batchStart, buf)
			if err != nil || n == 0 {
				i = j
				continue
			}

			for k := i; k < j; k++ {
				m := &pending[k]
				localOff := int(m.Address - batchStart)
				if localOff+vSize > n {
					continue
				}

				current := buf[localOff : localOff+vSize]
				keep := false

				switch filterType {
				case "exact":
					if newValue == nil {
						return fmt.Errorf("filter type 'exact' requires a value")
					}
					keep = bytes.Equal(current, newValue)
				case "changed":
					keep = !bytes.Equal(current, m.PrevData)
				case "unchanged":
					keep = bytes.Equal(current, m.PrevData)
				case "increased":
					keep = compareValues(session.valueType, current, m.PrevData, session.endian) > 0
				case "decreased":
					keep = compareValues(session.valueType, current, m.PrevData, session.endian) < 0
				default:
					return fmt.Errorf("unknown filter type %q", filterType)
				}

				if keep {
					if err := result.Add(scanMatch{
						Address:  m.Address,
						PrevData: cloneBytes(current),
					}); err != nil {
						return err
					}
				}
			}
			i = j
		}
		pending = pending[:0]
		return nil
	}

	// Iterate store in batches
	err := store.ForEachBatch(iterBatch, func(batch []scanMatch, _ int) error {
		pending = append(pending, batch...)
		return flushPending()
	})
	if err != nil {
		result.Close()
		return nil, err
	}

	return result, nil
}

// filterFromSnapshot performs the first filter on an unknown-value scan.
// Compares the snapshot (old values) with current process memory and applies
// the filter condition at every aligned offset. Produces a matchStore of
// addresses where the condition is met.
func filterFromSnapshot(reader ProcessReader, snap *memorySnapshot, vt ValueType, vSize int, endian binary.ByteOrder, filterType string, newValue []byte, protection string) (*matchStore, error) {
	if reader == nil {
		return nil, fmt.Errorf("process reader is closed")
	}
	if snap == nil {
		return nil, fmt.Errorf("no snapshot available")
	}

	// Copy index under lock, then use unlocked reads — caller holds session mutex,
	// so no concurrent access to this snapshot. (audit L1)
	snap.mu.Lock()
	regions := make([]snapRegion, len(snap.index))
	copy(regions, snap.index)
	snap.mu.Unlock()

	result := newMatchStore(vSize)
	const chunkSize = 64 * 1024 // 64KB compare chunks

	oldBuf := make([]byte, chunkSize)
	newBuf := make([]byte, chunkSize)

	for _, reg := range regions {
		for offset := uint64(0); offset < reg.Size; offset += uint64(chunkSize) {
			readLen := reg.Size - offset
			if readLen > uint64(chunkSize) {
				readLen = uint64(chunkSize)
			}

			addr := reg.BaseAddress + offset

			// Read from snapshot (unlocked — session mutex provides exclusivity)
			oldn, err := snap.readAtUnlocked(addr, oldBuf[:readLen])
			if err != nil || oldn < vSize {
				continue
			}

			// Read current from process
			newn, err := reader.ReadMemory(addr, newBuf[:readLen])
			if err != nil || newn < vSize {
				continue
			}

			minN := oldn
			if newn < minN {
				minN = newn
			}

			// Compare at every aligned offset
			for i := 0; i+vSize <= minN; i += vSize {
				old := oldBuf[i : i+vSize]
				cur := newBuf[i : i+vSize]

				keep := false
				switch filterType {
				case "exact":
					keep = bytes.Equal(cur, newValue)
				case "changed":
					keep = !bytes.Equal(cur, old)
				case "unchanged":
					keep = bytes.Equal(cur, old)
				case "increased":
					keep = compareValues(vt, cur, old, endian) > 0
				case "decreased":
					keep = compareValues(vt, cur, old, endian) < 0
				}

				if keep {
					if err := result.Add(scanMatch{
						Address:  addr + uint64(i),
						PrevData: cloneBytes(cur),
					}); err != nil {
						result.Close()
						return nil, err
					}
				}
			}
		}
	}

	return result, nil
}

// structSearch scans memory for a struct pattern (multiple values at known offsets).
func structSearch(reader ProcessReader, fields []structField, structSize int, protection string) ([]uint64, error) {
	regions, err := reader.Regions()
	if err != nil {
		return nil, err
	}

	var results []uint64
	const maxResults = 100_000

	anchor := &fields[0]
	anchorLen := len(anchor.encoded)

	chunk := make([]byte, scanChunkSize+structSize)

	for _, region := range regions {
		if protection != "" && !matchProtection(region.Protection, protection) {
			continue
		}
		if region.Size > 512*1024*1024 {
			continue
		}

		for offset := uint64(0); offset < region.Size; offset += scanChunkSize {
			readSize := region.Size - offset
			if readSize > uint64(scanChunkSize) {
				readSize = uint64(scanChunkSize)
			}
			extraSize := readSize + uint64(structSize)
			if extraSize > region.Size-offset {
				extraSize = region.Size - offset
			}

			buf := chunk[:extraSize]
			n, err := reader.ReadMemory(region.BaseAddress+offset, buf)
			if err != nil || n < structSize {
				continue
			}
			buf = buf[:n]

			searchEnd := len(buf) - structSize
			for i := 0; i <= searchEnd; i++ {
				if !bytes.Equal(buf[i+anchor.Offset:i+anchor.Offset+anchorLen], anchor.encoded) {
					continue
				}

				allMatch := true
				for j := 1; j < len(fields); j++ {
					f := &fields[j]
					fStart := i + f.Offset
					fEnd := fStart + len(f.encoded)
					if fEnd > len(buf) || !bytes.Equal(buf[fStart:fEnd], f.encoded) {
						allMatch = false
						break
					}
				}

				if allMatch {
					addr := region.BaseAddress + offset + uint64(i)
					results = append(results, addr)
					if len(results) >= maxResults {
						return results, nil
					}
				}
			}
		}
	}

	return results, nil
}
