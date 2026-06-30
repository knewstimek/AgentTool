package analyze

import (
	"encoding/binary"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// Ungated unit test for the switch jump-table resolver. Builds a synthetic
// section: a `jmp dword ptr [eax*4 + table]` followed (later) by a 3-entry table
// of absolute case VAs, and checks the resolver returns the three case offsets.
// A based-index form (`[ebx + eax*4]`, an array access) must NOT resolve.
func TestJumpTableResolver(t *testing.T) {
	const imageBase = 0x10000000
	const secRVA = 0x1000
	data := make([]byte, 0x400)

	// Table at section offset 0x100 -> RVA 0x1100 -> VA imageBase+0x1100.
	tableOff := 0x100
	tableVA := uint64(imageBase + secRVA + tableOff)
	cases := []int{0x40, 0x60, 0x80} // section offsets of case blocks
	for i, c := range cases {
		va := uint32(imageBase + secRVA + c)
		binary.LittleEndian.PutUint32(data[tableOff+i*4:], va)
	}
	// A 4th word that is NOT a valid in-section code VA ends the table.
	binary.LittleEndian.PutUint32(data[tableOff+len(cases)*4:], 0xDEADBEEF)

	// jmp dword ptr [eax*4 + tableVA]  ->  FF 24 85 <disp32> at offset 0.
	data[0] = 0xFF
	data[1] = 0x24
	data[2] = 0x85
	binary.LittleEndian.PutUint32(data[3:], uint32(tableVA))

	jt := makeJumpTableResolver([]tableSection{{rva: secRVA, data: data}}, data, secRVA, imageBase)
	inst, err := x86asm.Decode(data[0:], 32)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := jt(inst, 0)
	if len(got) != len(cases) {
		t.Fatalf("got %d targets %v, want %v", len(got), got, cases)
	}
	for i := range cases {
		if got[i] != cases[i] {
			t.Errorf("target[%d] = 0x%x, want 0x%x", i, got[i], cases[i])
		}
	}

	// Based-index array access must not be treated as a switch table.
	// jmp dword ptr [ebx + eax*4]  ->  FF 24 83 (mod=00, base=ebx, idx=eax*4).
	arr := []byte{0xFF, 0x24, 0x83}
	ai, err := x86asm.Decode(arr, 32)
	if err == nil {
		if r := jt(ai, 0); r != nil {
			t.Errorf("based-index array access resolved as table: %v", r)
		}
	}

	// A direct jmp (E9 rel32) is not an indirect table either.
	dj := []byte{0xE9, 0x00, 0x00, 0x00, 0x00}
	di, err := x86asm.Decode(dj, 32)
	if err == nil {
		if r := jt(di, 0); r != nil {
			t.Errorf("direct jmp resolved as table: %v", r)
		}
	}
}
