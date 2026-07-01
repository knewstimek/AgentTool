package memtool

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const (
	maxChains           = 64 // batch cap: one call resolves up to this many chains
	maxChainOffsets     = 16 // per-chain offset depth cap
	defaultChainDumpLen = 32 // hex dump length when a chain has no value type
)

// chainSpec is a single Cheat-Engine-style pointer chain to resolve.
// base is a pointer holder; offsets walk the chain. See resolveChain for semantics.
type chainSpec struct {
	Base    string        `json:"base"`
	Offsets []interface{} `json:"offsets"` // hex strings ("0x10", "-0x8") or numbers, signed
	Type    string        `json:"type"`    // value_type for the final read; empty = hex dump
	Label   string        `json:"label"`
	Length  int           `json:"length"` // read length for string/utf16/bytes/hexdump
	Endian  string        `json:"endian"` // per-chain override; empty = call default
}

// chainResult holds the outcome of resolving one chain.
type chainResult struct {
	label     string
	base      uint64
	offsets   []int64
	steps     []uint64 // dereferenced pointer at each stage: [base, deref(base), ...]
	finalAddr uint64
	brokenAt  int // -1 if fully resolved; else the step index that failed
	brokenMsg string
	valueType string
	valueStr  string
	rawHex    string
}

// resolveChain walks a pointer chain using Cheat-Engine semantics:
//
//	p = deref(base)
//	p = deref(p + off[0])   // for every offset except the last
//	...
//	finalAddr = p + off[last]   // last offset is NOT dereferenced
//	value = read(finalAddr, type)
//
// Special case: an empty offsets list reads directly at base (read_chain is a
// superset of read). On any unreadable dereference the chain is marked broken
// with the failing step, so the agent can see exactly where the chain died
// instead of getting a bare "read failed".
func resolveChain(reader ProcessReader, spec chainSpec, defBO binary.ByteOrder, ptrSize int) chainResult {
	res := chainResult{brokenAt: -1, label: spec.Label}

	base, err := parseAddress(spec.Base)
	if err != nil {
		res.brokenAt = 0
		res.brokenMsg = fmt.Sprintf("invalid base %q: %v", spec.Base, err)
		return res
	}
	res.base = base

	bo := defBO
	if strings.TrimSpace(spec.Endian) != "" {
		bo = getByteOrder(spec.Endian)
	}

	offs := make([]int64, 0, len(spec.Offsets))
	for i, ov := range spec.Offsets {
		o, err := parseOffset(ov)
		if err != nil {
			res.brokenAt = 0
			res.brokenMsg = fmt.Sprintf("invalid offset[%d]: %v", i, err)
			return res
		}
		offs = append(offs, o)
	}
	res.offsets = offs
	res.steps = append(res.steps, base)

	var finalAddr uint64
	if len(offs) == 0 {
		// No offsets: base is the final address (plain read).
		finalAddr = base
	} else {
		p, ok := derefPtr(reader, base, ptrSize, bo)
		if !ok {
			res.brokenAt = 1
			res.brokenMsg = fmt.Sprintf("deref base 0x%X failed (unreadable)", base)
			return res
		}
		res.steps = append(res.steps, p)

		// Every offset except the last is a dereference step.
		for i := 0; i < len(offs)-1; i++ {
			addr := uint64(int64(p) + offs[i])
			np, ok := derefPtr(reader, addr, ptrSize, bo)
			if !ok {
				res.brokenAt = i + 2
				res.brokenMsg = fmt.Sprintf("deref 0x%X (step %d) failed (unreadable)", addr, i+2)
				return res
			}
			p = np
			res.steps = append(res.steps, p)
		}
		finalAddr = uint64(int64(p) + offs[len(offs)-1])
	}
	res.finalAddr = finalAddr

	// Read and format the value at the final address.
	vtStr := strings.ToLower(strings.TrimSpace(spec.Type))
	if vtStr == "" {
		length := spec.Length
		if length <= 0 {
			length = defaultChainDumpLen
		}
		if length > 4096 {
			length = 4096
		}
		buf := make([]byte, length)
		n, err := reader.ReadMemory(finalAddr, buf)
		if err != nil && n == 0 {
			res.brokenAt = len(res.steps) + 1
			res.brokenMsg = fmt.Sprintf("read final 0x%X failed: %v", finalAddr, err)
			return res
		}
		res.valueType = "bytes"
		res.rawHex = fmtHexBytes(buf[:n])
		return res
	}

	vt, err := parseValueType(vtStr)
	if err != nil {
		res.brokenAt = len(res.steps) + 1
		res.brokenMsg = err.Error()
		return res
	}
	sz := valueSize(vt)
	if sz == 0 { // string/utf16/bytes: variable length
		sz = spec.Length
		if sz <= 0 {
			sz = 64
		}
		if sz > 4096 {
			sz = 4096
		}
	}
	buf := make([]byte, sz)
	n, err := reader.ReadMemory(finalAddr, buf)
	if err != nil && n == 0 {
		res.brokenAt = len(res.steps) + 1
		res.brokenMsg = fmt.Sprintf("read final 0x%X failed: %v", finalAddr, err)
		return res
	}
	res.valueType = valueTypeName(vt)
	res.valueStr = formatValue(vt, buf[:n], bo)
	res.rawHex = fmtHexBytes(buf[:n])
	return res
}

// derefPtr reads a pointer-sized value at addr. Returns false if fewer than
// ptrSize bytes are readable (chain is broken there).
func derefPtr(reader ProcessReader, addr uint64, ptrSize int, bo binary.ByteOrder) (uint64, bool) {
	buf := make([]byte, ptrSize)
	n, _ := reader.ReadMemory(addr, buf)
	if n < ptrSize {
		return 0, false
	}
	if ptrSize == 8 {
		return bo.Uint64(buf), true
	}
	return uint64(bo.Uint32(buf)), true
}

// parseOffset accepts a signed offset as a number or a hex/decimal string.
// strconv base 0 handles "0x10", "-0x8", "16", "-16".
func parseOffset(v interface{}) (int64, error) {
	switch t := v.(type) {
	case float64:
		return int64(t), nil
	case int:
		return int64(t), nil
	case int64:
		return t, nil
	case json.Number:
		return t.Int64()
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0, fmt.Errorf("empty offset")
		}
		n, err := strconv.ParseInt(s, 0, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid offset %q (use hex like 0x10 or decimal, may be negative)", s)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("offset must be a hex string or number")
	}
}

// parseFlatOffsets parses the single-chain 'offsets' param: a JSON array
// ("[\"0x10\",\"0x8\"]") or a comma/space separated list ("0x10, 0x8").
func parseFlatOffsets(s string) ([]interface{}, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if strings.HasPrefix(s, "[") {
		var arr []interface{}
		dec := json.NewDecoder(strings.NewReader(s))
		dec.UseNumber()
		if err := dec.Decode(&arr); err != nil {
			return nil, fmt.Errorf("invalid offsets JSON: %w", err)
		}
		return arr, nil
	}
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	out := make([]interface{}, len(fields))
	for i, f := range fields {
		out[i] = f
	}
	return out, nil
}

// formatChainResults renders all resolved chains compactly for the agent.
func formatChainResults(results []chainResult, ptrSize int) string {
	var sb strings.Builder
	okCount := 0
	for _, r := range results {
		if r.brokenAt < 0 {
			okCount++
		}
	}
	sb.WriteString(fmt.Sprintf("Pointer chains: %d/%d resolved (ptr size %d)\n", okCount, len(results), ptrSize))

	for _, r := range results {
		sb.WriteString("\n")
		label := r.label
		if label == "" {
			label = "chain"
		}
		offStr := formatOffsets(r.offsets)

		if r.brokenAt >= 0 {
			sb.WriteString(fmt.Sprintf("[%s] BROKEN at step %d: %s\n", label, r.brokenAt, r.brokenMsg))
			sb.WriteString(fmt.Sprintf("  base=0x%X  %s\n", r.base, offStr))
			if len(r.steps) > 0 {
				sb.WriteString("  trace: " + traceStr(r.steps) + " -> <null>\n")
			}
			continue
		}

		if r.valueStr != "" {
			sb.WriteString(fmt.Sprintf("[%s] %s @ 0x%X = %s\n", label, r.valueType, r.finalAddr, r.valueStr))
		} else {
			sb.WriteString(fmt.Sprintf("[%s] 0x%X: %s\n", label, r.finalAddr, r.rawHex))
		}
		sb.WriteString(fmt.Sprintf("  base=0x%X  %s\n", r.base, offStr))
		sb.WriteString("  trace: " + traceStr(append(r.steps, r.finalAddr)) + "\n")
	}
	return sb.String()
}

func formatOffsets(offs []int64) string {
	if len(offs) == 0 {
		return "(no offsets)"
	}
	parts := make([]string, len(offs))
	for i, o := range offs {
		if o < 0 {
			parts[i] = fmt.Sprintf("-0x%X", -o)
		} else {
			parts[i] = fmt.Sprintf("+0x%X", o)
		}
	}
	return strings.Join(parts, " ")
}

func traceStr(addrs []uint64) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = fmt.Sprintf("0x%X", a)
	}
	return strings.Join(parts, " -> ")
}
