package memtool

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func formatRegions(regions []MemoryRegion, maxResults int) string {
	var sb strings.Builder
	total := len(regions)
	sb.WriteString(fmt.Sprintf("Memory Regions: %d\n\n", total))
	if total == 0 {
		return sb.String()
	}

	sb.WriteString("Address              Size         Prot  Mapped\n")
	sb.WriteString("───────────────────  ───────────  ────  ──────\n")

	shown := total
	if maxResults > 0 && shown > maxResults {
		shown = maxResults
	}

	for i := 0; i < shown; i++ {
		r := &regions[i]
		sb.WriteString(fmt.Sprintf("0x%016X  %-11s  %-4s  %s\n",
			r.BaseAddress, formatSize(r.Size), r.Protection, r.MappedFile))
	}
	if total > shown {
		sb.WriteString(fmt.Sprintf("\n... +%d more regions\n", total-shown))
	}
	return sb.String()
}

func formatSearchResult(sessionID string, matchCount int, totalRegions int) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Session: %s\n", sessionID))
	sb.WriteString(fmt.Sprintf("Regions scanned: %d\n", totalRegions))
	sb.WriteString(fmt.Sprintf("Matches found: %s\n", formatCount(matchCount)))
	if matchCount >= matchAbsoluteMax {
		sb.WriteString(fmt.Sprintf("⚠ Capped at %s matches. Use a more specific value.\n", formatCount(matchAbsoluteMax)))
	}
	return sb.String()
}

func formatFilterResult(matchCount int, prevCount int) string {
	return fmt.Sprintf("Matches: %s (was %s)\n", formatCount(matchCount), formatCount(prevCount))
}

func formatSessionInfo(s *scanSession, reader ProcessReader, maxResults int) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Session: %s\n", s.id))
	sb.WriteString(fmt.Sprintf("PID: %d\n", s.pid))
	sb.WriteString(fmt.Sprintf("Type: %s (%s endian)\n", valueTypeName(s.valueType), endianName(s.endian)))
	if s.unknownScan {
		sb.WriteString("Scan type: unknown initial value (snapshot-based)\n")
		if s.snapshot != nil {
			sb.WriteString(fmt.Sprintf("Snapshot: %s\n", formatSize(uint64(s.snapshot.Size()))))
		}
		sb.WriteString("Use filter (changed, unchanged, increased, decreased, exact) to narrow down.\n")
		sb.WriteString(fmt.Sprintf("Undo available: %d\n", len(s.undoStack)))
		return sb.String()
	}
	sb.WriteString(fmt.Sprintf("Matches: %s\n", formatCount(s.matchCount)))
	sb.WriteString(fmt.Sprintf("Undo available: %d\n", len(s.undoStack)))

	if s.matchCount == 0 || s.store == nil {
		return sb.String()
	}

	if s.store.OnDisk() {
		sb.WriteString(fmt.Sprintf("Storage: disk-backed (%s on disk)\n", formatCount(s.matchCount)))
	}

	shown := s.matchCount
	if maxResults > 0 && shown > maxResults {
		shown = maxResults
	}

	sb.WriteString("\nAddress              Previous      Current\n")
	sb.WriteString("───────────────────  ────────────  ────────────\n")

	vSize := s.valueSize
	buf := make([]byte, vSize)

	// Read first 'shown' matches (works for both memory and disk)
	matches, _ := s.store.GetBatch(0, shown)
	for _, m := range matches {
		prevStr := formatValue(s.valueType, m.PrevData, s.endian)

		currentStr := "?"
		if reader != nil {
			n, err := reader.ReadMemory(m.Address, buf)
			if err == nil && n >= vSize {
				currentStr = formatValue(s.valueType, buf[:vSize], s.endian)
			}
		}
		sb.WriteString(fmt.Sprintf("0x%016X  %-12s  %s\n", m.Address, prevStr, currentStr))
	}
	if s.matchCount > shown {
		sb.WriteString(fmt.Sprintf("\n... +%s more\n", formatCount(s.matchCount-shown)))
	}
	return sb.String()
}

func formatHexDump(address uint64, data []byte) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Address: 0x%X, Length: %d bytes\n\n", address, len(data)))

	for offset := 0; offset < len(data); offset += 16 {
		sb.WriteString(fmt.Sprintf("%08X  ", address+uint64(offset)))

		end := offset + 16
		if end > len(data) {
			end = len(data)
		}

		for i := offset; i < offset+16; i++ {
			if i == offset+8 {
				sb.WriteByte(' ')
			}
			if i < end {
				sb.WriteString(fmt.Sprintf("%02X ", data[i]))
			} else {
				sb.WriteString("   ")
			}
		}

		sb.WriteString(" |")
		for i := offset; i < end; i++ {
			b := data[i]
			if b >= 0x20 && b < 0x7F {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

func formatWriteResult(address uint64, bytesWritten int, vt ValueType, data []byte, bo binary.ByteOrder) string {
	return fmt.Sprintf("Written %d bytes at 0x%X\nValue: %s", bytesWritten, address, formatValue(vt, data, bo))
}

func formatStructSearchResult(addresses []uint64, maxResults int) string {
	var sb strings.Builder
	total := len(addresses)
	sb.WriteString(fmt.Sprintf("Struct matches: %d\n\n", total))

	shown := total
	if maxResults > 0 && shown > maxResults {
		shown = maxResults
	}

	for i := 0; i < shown; i++ {
		sb.WriteString(fmt.Sprintf("0x%016X\n", addresses[i]))
	}
	if total > shown {
		sb.WriteString(fmt.Sprintf("\n... +%d more\n", total-shown))
	}
	return sb.String()
}

func formatPointerScanResult(chains []pointerChain, targetAddr uint64, bo binary.ByteOrder) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Pointer chains to 0x%X: %d found\n\n", targetAddr, len(chains)))

	for i, c := range chains {
		if i >= 200 {
			sb.WriteString(fmt.Sprintf("\n... +%d more chains\n", len(chains)-200))
			break
		}
		sb.WriteString(fmt.Sprintf("  [0x%X]", c.BaseAddress))
		for _, off := range c.Offsets {
			if off >= 0 {
				sb.WriteString(fmt.Sprintf(" +0x%X", off))
			} else {
				sb.WriteString(fmt.Sprintf(" -0x%X", -off))
			}
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

func formatDiffResult(diffs []diffEntry, maxResults int) string {
	var sb strings.Builder
	total := len(diffs)
	sb.WriteString(fmt.Sprintf("Memory differences: %d\n\n", total))

	if total == 0 {
		sb.WriteString("No changes detected.\n")
		return sb.String()
	}

	shown := total
	if maxResults > 0 && shown > maxResults {
		shown = maxResults
	}

	sb.WriteString("Address              Old          New\n")
	sb.WriteString("───────────────────  ───────────  ───────────\n")

	for i := 0; i < shown; i++ {
		d := &diffs[i]
		sb.WriteString(fmt.Sprintf("0x%016X  %-11s  %s\n", d.Address, fmtHexBytes(d.OldData), fmtHexBytes(d.NewData)))
	}
	if total > shown {
		sb.WriteString(fmt.Sprintf("\n... +%d more differences\n", total-shown))
	}
	return sb.String()
}

// diffEntry represents a single memory difference.
type diffEntry struct {
	Address uint64
	OldData []byte
	NewData []byte
}

func formatSize(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func formatCount(n int) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}
