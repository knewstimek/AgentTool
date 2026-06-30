package analyze

// Broad verification across real ordinal-only PEs before release: every sampled
// code export must resolve to itself at exact confidence, and a wide sweep of
// addresses must never crash or emit an empty result. Gated on AGENT_TOOL_D2_DIR.

import (
	"debug/pe"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// Every code export, queried at its own start, must come back as
// start_source: export / confidence: exact, pointing at itself.
func TestFunctionAtAllExportsResolveExact(t *testing.T) {
	dir := d2Dir(t)
	for _, name := range []string{"D2Game.dll", "D2Common.dll", "D2Client.dll", "D2Win.dll"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			f, err := pe.Open(path)
			if err != nil {
				t.Skipf("open %s: %v", name, err)
			}
			imageBase := peImageBase(f)
			starts, _ := codeExportStarts(f)
			f.Close()
			if len(starts) == 0 {
				t.Skipf("%s: no code exports", name)
			}
			// Sample up to ~40 exports spread across the table to bound runtime.
			step := 1
			if len(starts) > 40 {
				step = len(starts) / 40
			}
			checked, bad := 0, 0
			for i := 0; i < len(starts); i += step {
				rva := starts[i]
				va := imageBase + uint64(rva)
				out, err := opFunctionAt(AnalyzeInput{Operation: "function_at", FilePath: path, VA: fmt.Sprintf("0x%x", va), Count: 1})
				if err != nil {
					t.Errorf("%s: function_at 0x%x errored: %v", name, va, err)
					bad++
					continue
				}
				checked++
				if !strings.Contains(out, "start_source: export") || !strings.Contains(out, "confidence:   exact") {
					t.Errorf("%s: export 0x%x did not resolve exact:\n%s", name, va, out)
					bad++
					continue
				}
				if !strings.Contains(out, fmt.Sprintf("Start:  0x%x", va)) {
					t.Errorf("%s: export 0x%x resolved to a different start:\n%s", name, va, out)
					bad++
				}
			}
			t.Logf("%s: %d exports checked, %d bad", name, checked, bad)
		})
	}
}

// The x64 .pdata path (unchanged logic, now also emitting start_source/confidence)
// must still resolve a known .pdata function as pdata/exact. Uses the repo's own
// x64 build as the fixture; skips if it has no exception table.
func TestFunctionAtX64PdataPath(t *testing.T) {
	f, err := pe.Open(testBinary)
	if err != nil {
		t.Skip(err)
	}
	imageBase := peImageBase(f)
	table := buildFuncTable(f, imageBase)
	f.Close()
	if len(table) == 0 {
		t.Skip("fixture has no .pdata")
	}
	va := imageBase + uint64(table[len(table)/2].begin)
	out, err := opFunctionAt(AnalyzeInput{Operation: "function_at", FilePath: testBinary, VA: fmt.Sprintf("0x%x", va), Count: 1})
	if err != nil {
		t.Fatalf("function_at: %v", err)
	}
	if !strings.Contains(out, "start_source: pdata") || !strings.Contains(out, "confidence:   exact") {
		t.Errorf("x64 .pdata path: expected pdata/exact, got:\n%s", out)
	}
}

// A wide sweep of code addresses must never panic and must always produce a
// non-empty result (a real answer or a graceful error string), with no result
// ever claiming both a misaligned start AND exact/high confidence.
func TestFunctionAtSweepNoCrash(t *testing.T) {
	dir := d2Dir(t)
	path := filepath.Join(dir, "D2Game.dll")
	f, err := pe.Open(path)
	if err != nil {
		t.Skip(err)
	}
	imageBase := peImageBase(f)
	// Find .text (first executable section) extent.
	var secRVA, secLen uint32
	for _, s := range f.Sections {
		if s.Characteristics&0x20000000 != 0 {
			secRVA = s.VirtualAddress
			secLen = s.VirtualSize
			break
		}
	}
	f.Close()
	if secLen == 0 {
		t.Skip("no exec section")
	}

	// Sample every 4KB across .text.
	for off := uint32(0); off < secLen; off += 0x1000 {
		va := imageBase + uint64(secRVA+off)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC at 0x%x: %v", va, r)
				}
			}()
			out, err := opFunctionAt(AnalyzeInput{Operation: "function_at", FilePath: path, VA: fmt.Sprintf("0x%x", va), Count: 1})
			if err != nil {
				return // graceful error is acceptable
			}
			if strings.TrimSpace(out) == "" {
				t.Errorf("0x%x: empty output", va)
			}
			// A misaligned start must never be labeled exact/high.
			if strings.Contains(out, "heuristic-misaligned") &&
				(strings.Contains(out, "confidence:   exact") || strings.Contains(out, "confidence:   high")) {
				t.Errorf("0x%x: misaligned start with exact/high confidence:\n%s", va, out)
			}
		}()
	}
}
