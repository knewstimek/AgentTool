package memtool

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"agent-tool/common"
	"agent-tool/tools/analyze"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MemtoolInput defines parameters for all memtool operations.
type MemtoolInput struct {
	// Resolved int values set by Handle after FlexInt conversion.
	PIDInt        int `json:"-"`
	LengthInt     int `json:"-"`
	MaxResultsInt int `json:"-"`
	MaxDepthInt   int `json:"-"`
	MaxOffsetInt  int `json:"-"`
	ModeInt       int `json:"-"`
	CountInt      int `json:"-"`

	Operation     string `json:"operation" jsonschema:"Operation: regions, search, filter, read, write, disasm, info, close, undo, struct_search, pointer_scan, diff,required"`
	PID           interface{} `json:"pid,omitempty" jsonschema:"Target process ID (for regions, search, read, write, disasm, struct_search, pointer_scan, diff)"`
	SessionID     string `json:"session_id,omitempty" jsonschema:"Session ID from a previous search (for filter, info, close, undo, diff)"`
	ValueType     string `json:"value_type,omitempty" jsonschema:"Value type: int8/16/32/64, uint8/16/32/64, float32/64, string, utf16, bytes"`
	Value         string `json:"value,omitempty" jsonschema:"Search/write value (number for numeric types, text for string/utf16, hex bytes like '4D 5A 90' for bytes). Omit for unknown initial value scan."`
	Endian        string `json:"endian,omitempty" jsonschema:"Byte order: little (default) or big"`
	FilterType    string `json:"filter_type,omitempty" jsonschema:"Filter: exact, changed, unchanged, increased, decreased"`
	Address       string `json:"address,omitempty" jsonschema:"Hex address (e.g. '0x7FF6A1B20000') for read/write/disasm/pointer_scan"`
	Length        interface{} `json:"length,omitempty" jsonschema:"Bytes to read/disasm (default 256 for read, 64 for disasm, max 4096)"`
	Protection    string `json:"protection,omitempty" jsonschema:"Filter by protection: r, rw, rx"`
	MaxResults    interface{} `json:"max_results,omitempty" jsonschema:"Max results to display (default 100, max 1000)"`
	StructPattern string `json:"struct_pattern,omitempty" jsonschema:"JSON array for struct search: [{offset:0,type:'int32',value:'100'},{offset:4,type:'int32',value:'50'}]"`
	MaxDepth      interface{} `json:"max_depth,omitempty" jsonschema:"Pointer scan max chain depth (default 3, max 5)"`
	MaxOffset     interface{} `json:"max_offset,omitempty" jsonschema:"Pointer scan max offset from target (default 0x1000)"`
	Arch          string `json:"arch,omitempty" jsonschema:"CPU architecture for disasm: x86 (default) or arm"`
	Mode          interface{} `json:"mode,omitempty" jsonschema:"CPU mode for disasm: 32 or 64 (default)"`
	Count         interface{} `json:"count,omitempty" jsonschema:"Number of instructions to disassemble (default 50, max 200)"`
}

// MemtoolOutput is the output structure.
type MemtoolOutput struct {
	Result string `json:"result"`
}

var validOps = map[string]bool{
	"regions": true, "search": true, "filter": true,
	"read": true, "write": true, "disasm": true, "info": true, "close": true,
	"undo": true, "struct_search": true, "pointer_scan": true, "diff": true,
}

// Handle processes a memtool invocation.
func Handle(ctx context.Context, req *mcp.CallToolRequest, input MemtoolInput) (*mcp.CallToolResult, MemtoolOutput, error) {
	op := strings.ToLower(strings.TrimSpace(input.Operation))
	if !validOps[op] {
		return errorResult("invalid operation %q (use: regions, search, filter, read, write, disasm, info, close, undo, struct_search, pointer_scan, diff)", op)
	}

	// Resolve all integer fields upfront to support string-encoded values from XML tool calls
	var ok bool
	input.PIDInt, _ = common.FlexInt(input.PID)
	input.LengthInt, _ = common.FlexInt(input.Length)
	input.MaxDepthInt, _ = common.FlexInt(input.MaxDepth)
	input.MaxOffsetInt, _ = common.FlexInt(input.MaxOffset)
	input.ModeInt, _ = common.FlexInt(input.Mode)
	input.CountInt, _ = common.FlexInt(input.Count)
	input.MaxResultsInt, ok = common.FlexInt(input.MaxResults)
	if !ok {
		return errorResult("max_results must be an integer")
	}

	if input.MaxResultsInt <= 0 {
		input.MaxResultsInt = 100
	}
	if input.MaxResultsInt > 1000 {
		input.MaxResultsInt = 1000
	}

	switch op {
	case "regions":
		return opRegions(input)
	case "search":
		return opSearch(input)
	case "filter":
		return opFilter(input)
	case "read":
		return opRead(input)
	case "write":
		return opWrite(input)
	case "disasm":
		return opDisasm(input)
	case "info":
		return opInfo(input)
	case "close":
		return opClose(input)
	case "undo":
		return opUndo(input)
	case "struct_search":
		return opStructSearch(input)
	case "pointer_scan":
		return opPointerScan(input)
	case "diff":
		return opDiff(input)
	default:
		return errorResult("unhandled: %s", op)
	}
}

func opRegions(input MemtoolInput) (*mcp.CallToolResult, MemtoolOutput, error) {
	if input.PIDInt <= 0 {
		return errorResult("pid is required")
	}

	reader := newProcessReader()
	if err := reader.Open(input.PIDInt, false); err != nil {
		return errorResult("%v", err)
	}
	defer reader.Close()

	regions, err := reader.Regions()
	if err != nil {
		return errorResult("%v", err)
	}

	if input.Protection != "" {
		var filtered []MemoryRegion
		for _, r := range regions {
			if matchProtection(r.Protection, input.Protection) {
				filtered = append(filtered, r)
			}
		}
		regions = filtered
	}

	return successResult(formatRegions(regions, input.MaxResultsInt))
}

func opSearch(input MemtoolInput) (*mcp.CallToolResult, MemtoolOutput, error) {
	if input.PIDInt <= 0 {
		return errorResult("pid is required")
	}
	if input.ValueType == "" {
		return errorResult("value_type is required")
	}

	vt, err := parseValueType(input.ValueType)
	if err != nil {
		return errorResult("%v", err)
	}
	bo := getByteOrder(input.Endian)

	// Unknown initial value scan: no value given → take snapshot of all memory.
	// Filter later with changed/unchanged/increased/decreased.
	if input.Value == "" {
		vSz := valueSize(vt)
		if vSz == 0 {
			return errorResult("unknown scan requires a fixed-size value_type (not string/bytes)")
		}

		reader := newProcessReader()
		if err := reader.Open(input.PIDInt, false); err != nil {
			return errorResult("%v", err)
		}

		snap, regions, err := takeSnapshot(reader, input.Protection)
		if err != nil {
			reader.Close()
			return errorResult("snapshot failed: %v", err)
		}

		now := time.Now()
		session := &scanSession{
			id:          newSessionID(),
			pid:         input.PIDInt,
			valueType:   vt,
			valueSize:   vSz,
			endian:      bo,
			snapshot:    snap,
			unknownScan: true,
			reader:      reader,
			createdAt:   now,
			lastUsed:    now,
		}

		if err := pool.add(session); err != nil {
			reader.Close()
			snap.Close()
			return errorResult("%v", err)
		}

		return successResult(fmt.Sprintf(
			"Unknown initial value scan.\nSession: %s\nType: %s\nSnapshot: %s (%d regions)\nUse filter to narrow down (changed, unchanged, increased, decreased, exact).",
			session.id, input.ValueType, formatSize(uint64(snap.Size())), len(regions)))
	}

	pattern, err := encodeValue(vt, input.Value, bo)
	if err != nil {
		return errorResult("invalid value: %v", err)
	}

	reader := newProcessReader()
	if err := reader.Open(input.PIDInt, false); err != nil {
		return errorResult("%v", err)
	}

	regions, err := reader.Regions()
	if err != nil {
		reader.Close()
		return errorResult("%v", err)
	}
	totalRegions := len(regions)

	vSz := valueSize(vt)
	if vSz == 0 {
		vSz = len(pattern)
	}

	store, err := searchMemory(reader, pattern, vt, vSz, input.Protection)
	if err != nil {
		reader.Close()
		return errorResult("scan failed: %v", err)
	}

	now := time.Now()
	session := &scanSession{
		id:         newSessionID(),
		pid:        input.PIDInt,
		valueType:  vt,
		valueSize:  vSz,
		endian:     bo,
		store:      store,
		matchCount: store.Count(),
		reader:     reader,
		createdAt:  now,
		lastUsed:   now,
	}

	if err := pool.add(session); err != nil {
		reader.Close()
		store.Close()
		return errorResult("%v", err)
	}

	return successResult(formatSearchResult(session.id, store.Count(), totalRegions))
}

func opFilter(input MemtoolInput) (*mcp.CallToolResult, MemtoolOutput, error) {
	if input.SessionID == "" {
		return errorResult("session_id is required")
	}
	if input.FilterType == "" {
		return errorResult("filter_type is required (exact, changed, unchanged, increased, decreased)")
	}

	session, ok := pool.get(input.SessionID)
	if !ok {
		return errorResult("session %q not found", input.SessionID)
	}
	defer session.release()
	session.mu.Lock()
	defer session.mu.Unlock()

	if session.reader == nil {
		return errorResult("session reader is closed")
	}

	var newValue []byte
	var err error
	if input.FilterType == "exact" {
		if input.Value == "" {
			return errorResult("value is required for filter_type 'exact'")
		}
		newValue, err = encodeValue(session.valueType, input.Value, session.endian)
		if err != nil {
			return errorResult("invalid value: %v", err)
		}
	}

	session.pushUndo()
	prevCount := session.matchCount

	var newStore *matchStore

	if session.unknownScan && session.snapshot != nil {
		// First filter on unknown-value scan: compare snapshot vs current memory
		newStore, err = filterFromSnapshot(
			session.reader, session.snapshot,
			session.valueType, session.valueSize, session.endian,
			input.FilterType, newValue, "",
		)
		if err != nil {
			session.popUndo() // rollback failed filter (audit M1)
			return errorResult("filter failed: %v", err)
		}
		// Transition from snapshot-based to matchStore-based
		session.unknownScan = false
	} else {
		newStore, err = filterMatches(session.reader, session, input.FilterType, newValue)
		if err != nil {
			session.popUndo() // rollback failed filter (audit M1)
			return errorResult("filter failed: %v", err)
		}
	}

	session.store = newStore
	session.matchCount = newStore.Count()

	return successResult(formatFilterResult(newStore.Count(), prevCount))
}

func opRead(input MemtoolInput) (*mcp.CallToolResult, MemtoolOutput, error) {
	if input.PIDInt <= 0 {
		return errorResult("pid is required")
	}
	if input.Address == "" {
		return errorResult("address is required (hex, e.g. '0x7FF6A1B20000')")
	}

	addr, err := parseAddress(input.Address)
	if err != nil {
		return errorResult("%v", err)
	}

	length := input.LengthInt
	if length <= 0 {
		length = 256
	}
	if length > 4096 {
		length = 4096
	}

	reader := newProcessReader()
	if err := reader.Open(input.PIDInt, false); err != nil {
		return errorResult("%v", err)
	}
	defer reader.Close()

	buf := make([]byte, length)
	n, err := reader.ReadMemory(addr, buf)
	if err != nil && n == 0 {
		return errorResult("read failed at 0x%X: %v", addr, err)
	}

	return successResult(formatHexDump(addr, buf[:n]))
}

func opWrite(input MemtoolInput) (*mcp.CallToolResult, MemtoolOutput, error) {
	if input.PIDInt <= 0 {
		return errorResult("pid is required")
	}
	if input.Address == "" {
		return errorResult("address is required")
	}
	if input.ValueType == "" {
		return errorResult("value_type is required")
	}
	if input.Value == "" {
		return errorResult("value is required")
	}

	addr, err := parseAddress(input.Address)
	if err != nil {
		return errorResult("%v", err)
	}

	vt, err := parseValueType(input.ValueType)
	if err != nil {
		return errorResult("%v", err)
	}

	bo := getByteOrder(input.Endian)
	data, err := encodeValue(vt, input.Value, bo)
	if err != nil {
		return errorResult("invalid value: %v", err)
	}

	// Cap write size to prevent accidents
	if len(data) > 4096 {
		return errorResult("write data too large (%d bytes, max 4096)", len(data))
	}

	reader := newProcessReader()
	if err := reader.Open(input.PIDInt, true); err != nil {
		return errorResult("%v", err)
	}
	defer reader.Close()

	n, err := reader.WriteMemory(addr, data)
	if err != nil {
		return errorResult("write failed at 0x%X: %v", addr, err)
	}

	return successResult(formatWriteResult(addr, n, vt, data, bo))
}

func opDisasm(input MemtoolInput) (*mcp.CallToolResult, MemtoolOutput, error) {
	if input.PIDInt <= 0 {
		return errorResult("pid is required")
	}
	if input.Address == "" {
		return errorResult("address is required (hex, e.g. '0x7FF6A1B20000')")
	}

	addr, err := parseAddress(input.Address)
	if err != nil {
		return errorResult("%v", err)
	}

	// Default: read enough bytes for the requested instruction count
	count := input.CountInt
	if count <= 0 {
		count = 50
	}
	if count > 200 {
		count = 200
	}

	arch := strings.ToLower(strings.TrimSpace(input.Arch))
	if arch == "" {
		arch = "x86"
	}
	mode := input.ModeInt
	if mode == 0 {
		mode = 64
	}

	// Calculate read size: x86 up to 15 bytes/inst, ARM fixed 4 bytes/inst
	var maxInstLen int
	if arch == "arm" {
		maxInstLen = 4
	} else {
		maxInstLen = 15
	}

	readSize := count * maxInstLen
	if readSize > 4096 {
		readSize = 4096
	}

	reader := newProcessReader()
	if err := reader.Open(input.PIDInt, false); err != nil {
		return errorResult("%v", err)
	}
	defer reader.Close()

	buf := make([]byte, readSize)
	n, err := reader.ReadMemory(addr, buf)
	if err != nil && n == 0 {
		return errorResult("read failed at 0x%X: %v", addr, err)
	}

	result, err := analyze.DisasmBytes(buf[:n], addr, arch, mode, count)
	if err != nil {
		return errorResult("disassembly failed: %v", err)
	}

	return successResult(fmt.Sprintf("Disassembly at 0x%X (PID %d):\n\n%s", addr, input.PIDInt, result))
}

func opInfo(input MemtoolInput) (*mcp.CallToolResult, MemtoolOutput, error) {
	if input.SessionID == "" {
		return errorResult("session_id is required")
	}

	session, ok := pool.get(input.SessionID)
	if !ok {
		return errorResult("session %q not found", input.SessionID)
	}
	defer session.release()
	session.mu.Lock()
	defer session.mu.Unlock()

	return successResult(formatSessionInfo(session, session.reader, input.MaxResultsInt))
}

func opClose(input MemtoolInput) (*mcp.CallToolResult, MemtoolOutput, error) {
	if input.SessionID == "" {
		return errorResult("session_id is required")
	}
	if pool.remove(input.SessionID) {
		return successResult(fmt.Sprintf("Session %s closed.", input.SessionID))
	}
	return errorResult("session %q not found", input.SessionID)
}

func opUndo(input MemtoolInput) (*mcp.CallToolResult, MemtoolOutput, error) {
	if input.SessionID == "" {
		return errorResult("session_id is required")
	}

	session, ok := pool.get(input.SessionID)
	if !ok {
		return errorResult("session %q not found", input.SessionID)
	}
	defer session.release()
	session.mu.Lock()
	defer session.mu.Unlock()

	if !session.popUndo() {
		return errorResult("no undo history available")
	}

	return successResult(fmt.Sprintf("Undo successful. Matches restored: %s", formatCount(session.matchCount)))
}

func opStructSearch(input MemtoolInput) (*mcp.CallToolResult, MemtoolOutput, error) {
	if input.PIDInt <= 0 {
		return errorResult("pid is required")
	}
	if input.StructPattern == "" {
		return errorResult("struct_pattern is required (JSON array: [{\"offset\":0,\"type\":\"int32\",\"value\":\"100\"}])")
	}

	bo := getByteOrder(input.Endian)
	fields, structSize, err := parseStructPattern(input.StructPattern, bo)
	if err != nil {
		return errorResult("%v", err)
	}

	reader := newProcessReader()
	if err := reader.Open(input.PIDInt, false); err != nil {
		return errorResult("%v", err)
	}
	defer reader.Close()

	addresses, err := structSearch(reader, fields, structSize, input.Protection)
	if err != nil {
		return errorResult("struct search failed: %v", err)
	}

	return successResult(formatStructSearchResult(addresses, input.MaxResultsInt))
}

func opPointerScan(input MemtoolInput) (*mcp.CallToolResult, MemtoolOutput, error) {
	if input.PIDInt <= 0 {
		return errorResult("pid is required")
	}
	if input.Address == "" {
		return errorResult("address is required (target address to find pointer chains to)")
	}

	addr, err := parseAddress(input.Address)
	if err != nil {
		return errorResult("%v", err)
	}

	reader := newProcessReader()
	if err := reader.Open(input.PIDInt, false); err != nil {
		return errorResult("%v", err)
	}
	defer reader.Close()

	maxDepth := input.MaxDepthInt
	if maxDepth <= 0 {
		maxDepth = 3
	}
	maxOffset := input.MaxOffsetInt
	if maxOffset <= 0 {
		maxOffset = pointerScanMaxOffset
	}

	chains, err := pointerScan(reader, addr, maxDepth, maxOffset, pointerSize(), input.Protection)
	if err != nil {
		return errorResult("pointer scan failed: %v", err)
	}

	bo := getByteOrder(input.Endian)
	return successResult(formatPointerScanResult(chains, addr, bo))
}

func opDiff(input MemtoolInput) (*mcp.CallToolResult, MemtoolOutput, error) {
	if input.PIDInt <= 0 && input.SessionID == "" {
		return errorResult("pid or session_id is required for diff")
	}

	// If session exists, use its reader and compare with snapshot
	if input.SessionID != "" {
		session, ok := pool.get(input.SessionID)
		if !ok {
			return errorResult("session %q not found", input.SessionID)
		}
		defer session.release()
		session.mu.Lock()
		defer session.mu.Unlock()

		if session.reader == nil {
			return errorResult("session reader is closed")
		}

		// First call: take snapshot and store it
		if session.snapshot == nil {
			snap, _, err := takeSnapshot(session.reader, input.Protection)
			if err != nil {
				return errorResult("snapshot failed: %v", err)
			}
			session.snapshot = snap
			return successResult(fmt.Sprintf("Snapshot taken (%s). Call diff again to compare.", formatSize(uint64(snap.Size()))))
		}

		// Second call: compare snapshot with current memory
		diffs, err := compareWithSnapshot(session.reader, session.snapshot, input.MaxResultsInt)
		if err != nil {
			return errorResult("diff failed: %v", err)
		}

		// Replace snapshot: close old first, set nil to avoid dangling on failure (audit M4)
		session.snapshot.Close()
		session.snapshot = nil
		snap, _, err := takeSnapshot(session.reader, input.Protection)
		if err != nil {
			return errorResult("snapshot update failed: %v", err)
		}
		session.snapshot = snap

		return successResult(formatDiffResult(diffs, input.MaxResultsInt))
	}

	// No session: create a temporary one-shot snapshot
	reader := newProcessReader()
	if err := reader.Open(input.PIDInt, false); err != nil {
		return errorResult("%v", err)
	}

	snap, _, err := takeSnapshot(reader, input.Protection)
	if err != nil {
		reader.Close()
		return errorResult("snapshot failed: %v", err)
	}

	// Create a session to hold the snapshot for the next diff call
	now := time.Now()
	session := &scanSession{
		id:        newSessionID(),
		pid:       input.PIDInt,
		reader:    reader,
		snapshot:  snap,
		endian:    getByteOrder(input.Endian),
		createdAt: now,
		lastUsed:  now,
	}
	if err := pool.add(session); err != nil {
		reader.Close()
		snap.Close()
		return errorResult("%v", err)
	}

	return successResult(fmt.Sprintf("Snapshot taken (%s).\nSession: %s\nCall diff again with this session_id to compare.", formatSize(uint64(snap.Size())), session.id))
}

// compareWithSnapshot compares current memory with a disk snapshot.
// Reads in chunks to minimize memory usage.
func compareWithSnapshot(reader ProcessReader, snap *memorySnapshot, maxDiffs int) ([]diffEntry, error) {
	var diffs []diffEntry
	if maxDiffs <= 0 {
		maxDiffs = 1000
	}

	snap.mu.Lock()
	regions := make([]snapRegion, len(snap.index))
	copy(regions, snap.index)
	snap.mu.Unlock()

	const compareChunk = 4096
	oldBuf := make([]byte, compareChunk)
	newBuf := make([]byte, compareChunk)

	for _, reg := range regions {
		for offset := uint64(0); offset < reg.Size; offset += compareChunk {
			readLen := reg.Size - offset
			if readLen > compareChunk {
				readLen = compareChunk
			}

			addr := reg.BaseAddress + offset

			// Read from snapshot
			oldn, err := snap.ReadAt(addr, oldBuf[:readLen])
			if err != nil || oldn == 0 {
				continue
			}

			// Read current from process
			newn, err := reader.ReadMemory(addr, newBuf[:readLen])
			if err != nil || newn == 0 {
				continue
			}

			minN := oldn
			if newn < minN {
				minN = newn
			}

			// Compare byte by byte, report differences at 4-byte granularity
			for i := 0; i+4 <= minN; i += 4 {
				if oldBuf[i] != newBuf[i] || oldBuf[i+1] != newBuf[i+1] ||
					oldBuf[i+2] != newBuf[i+2] || oldBuf[i+3] != newBuf[i+3] {
					diffs = append(diffs, diffEntry{
						Address: addr + uint64(i),
						OldData: cloneBytes(oldBuf[i : i+4]),
						NewData: cloneBytes(newBuf[i : i+4]),
					})
					if len(diffs) >= maxDiffs {
						return diffs, nil
					}
				}
			}
		}
	}

	return diffs, nil
}

// Register registers the memtool with the MCP server.
func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "memtool",
		Description: `Process memory tool for reverse engineering and game hacking.
CheatEngine-style workflow: search → filter → filter → find exact addresses → write.
Supported: Windows (ReadProcessMemory/WriteProcessMemory), Linux (/proc/pid/mem). macOS: not supported (SIP).
Operations: regions (list memory map), search (value scan or unknown initial value scan, creates session),
filter (narrow: exact/changed/unchanged/increased/decreased), undo (restore previous filter),
read (hex dump), write (modify memory), disasm (disassemble live memory — x86/x64/ARM/ARM64),
info (session status + values), close (end session),
struct_search (multi-field pattern), pointer_scan (find pointer chains to address),
diff (compare memory snapshots).`,
	}, Handle)
}

func parseAddress(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	addr, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid address %q: %w", s, err)
	}
	return addr, nil
}

func successResult(msg string) (*mcp.CallToolResult, MemtoolOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, MemtoolOutput{Result: msg}, nil
}

func errorResult(format string, args ...any) (*mcp.CallToolResult, MemtoolOutput, error) {
	msg := fmt.Sprintf(format, args...)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, MemtoolOutput{Result: msg}, nil
}
