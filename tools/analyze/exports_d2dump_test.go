package analyze

import (
	"debug/pe"
	"path/filepath"
	"testing"
)

// Pins exact ordinal -> RVA mappings for D2Game.dll, verified independently by
// disassembling each target (all land on instruction boundaries / prologues).
// This locks the export-table read (ordinal Base bias + AddressOfFunctions
// indexing) so a regression in parseExports is caught immediately.
//
// Note: an earlier agent claim that "Ord 10023 = spawn @ 0x6fc67515" was wrong
// on both counts -- 0x6fc67515 is mid-instruction (inside a `mov edx, imm32`),
// and Ord 10023 actually resolves to a tiny stub at RVA 0x46b10. The whole point
// of export ground truth is to make that class of heuristic mislabel impossible.
func TestD2GameExportAnchors(t *testing.T) {
	dir := d2Dir(t)
	f, err := pe.Open(filepath.Join(dir, "D2Game.dll"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	byOrd := make(map[uint32]uint32)
	for _, e := range parseExports(f) {
		byOrd[e.ordinal] = e.rva
	}

	// Verified by disassembly (clean prologues / valid instruction starts).
	want := map[uint32]uint32{
		10000: 0x2b840, // push ebx; mov ebx,[esp+0xc]; push ebp
		10001: 0x2b350, // push ecx; push ebx; push ebp
		10007: 0x29ad0, // mov eax,[esp+4]; ret 0x4  (getter stub)
		10023: 0x46b10, // ret 0x4  (stub export -- NOT the spawn func the agent claimed)
	}
	for ord, rva := range want {
		got, ok := byOrd[ord]
		if !ok {
			t.Errorf("Ord %d missing from exports", ord)
			continue
		}
		if got != rva {
			t.Errorf("Ord %d: got RVA 0x%x, want 0x%x", ord, got, rva)
		}
	}

	// Ordinal base must be applied: the first export is ordinal 10000, not 0/1.
	if _, ok := byOrd[10000]; !ok {
		t.Errorf("ordinal base not applied: Ord 10000 absent")
	}
}
