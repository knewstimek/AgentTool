package memtool

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// fakeMem is an in-memory ProcessReader for deterministic chain tests.
type fakeMem struct{ m map[uint64]byte }

func newFakeMem() *fakeMem { return &fakeMem{m: map[uint64]byte{}} }

func (f *fakeMem) put64(addr, val uint64) {
	for i := 0; i < 8; i++ {
		f.m[addr+uint64(i)] = byte(val >> (8 * uint(i)))
	}
}
func (f *fakeMem) put32(addr uint64, val uint32) {
	for i := 0; i < 4; i++ {
		f.m[addr+uint64(i)] = byte(val >> (8 * uint(i)))
	}
}
func (f *fakeMem) Open(pid int, writable, forceDACL bool) error { return nil }
func (f *fakeMem) Close()                                       {}
func (f *fakeMem) Regions() ([]MemoryRegion, error)            { return nil, nil }
func (f *fakeMem) ReadMemory(addr uint64, buf []byte) (int, error) {
	for i := range buf {
		b, ok := f.m[addr+uint64(i)]
		if !ok {
			return i, fmt.Errorf("unreadable at 0x%X", addr+uint64(i))
		}
		buf[i] = b
	}
	return len(buf), nil
}
func (f *fakeMem) WriteMemory(addr uint64, data []byte) (int, error) { return len(data), nil }

func TestResolveChainCEStandard(t *testing.T) {
	mem := newFakeMem()
	// base(0x1000) -> 0x2000 ; [0x2000+0x10]=0x3000 ; int32 @ 0x3000+0x8 = 12345
	mem.put64(0x1000, 0x2000)
	mem.put64(0x2010, 0x3000)
	mem.put32(0x3008, 12345)

	spec := chainSpec{Base: "0x1000", Offsets: []interface{}{"0x10", "0x8"}, Type: "int32", Label: "hp"}
	r := resolveChain(mem, spec, binary.LittleEndian, 8)

	if r.brokenAt >= 0 {
		t.Fatalf("expected resolved chain, got broken: %s", r.brokenMsg)
	}
	if r.finalAddr != 0x3008 {
		t.Fatalf("finalAddr = 0x%X, want 0x3008", r.finalAddr)
	}
	if r.valueStr != "12345" {
		t.Fatalf("value = %q, want 12345", r.valueStr)
	}
}

func TestResolveChainEmptyOffsets(t *testing.T) {
	mem := newFakeMem()
	mem.put32(0x3008, 999) // read directly at base, no deref

	spec := chainSpec{Base: "0x3008", Type: "int32"}
	r := resolveChain(mem, spec, binary.LittleEndian, 8)
	if r.brokenAt >= 0 {
		t.Fatalf("unexpected broken: %s", r.brokenMsg)
	}
	if r.finalAddr != 0x3008 || r.valueStr != "999" {
		t.Fatalf("got final=0x%X value=%q, want 0x3008/999", r.finalAddr, r.valueStr)
	}
}

func TestResolveChainBrokenReportsStep(t *testing.T) {
	mem := newFakeMem()
	mem.put64(0x1000, 0x2000) // deref base ok
	// 0x2000+0x10 is NOT mapped -> deref fails at step 2

	spec := chainSpec{Base: "0x1000", Offsets: []interface{}{"0x10", "0x8"}, Type: "int32"}
	r := resolveChain(mem, spec, binary.LittleEndian, 8)
	if r.brokenAt != 2 {
		t.Fatalf("brokenAt = %d, want 2 (%s)", r.brokenAt, r.brokenMsg)
	}
}

func TestResolveChainNegativeOffset(t *testing.T) {
	mem := newFakeMem()
	mem.put64(0x1000, 0x2000)
	mem.put32(0x1FF8, 77) // 0x2000 + (-0x8) = 0x1FF8

	spec := chainSpec{Base: "0x1000", Offsets: []interface{}{"-0x8"}, Type: "int32"}
	r := resolveChain(mem, spec, binary.LittleEndian, 8)
	if r.brokenAt >= 0 {
		t.Fatalf("unexpected broken: %s", r.brokenMsg)
	}
	if r.finalAddr != 0x1FF8 || r.valueStr != "77" {
		t.Fatalf("got final=0x%X value=%q, want 0x1FF8/77", r.finalAddr, r.valueStr)
	}
}

func TestResolveChain32Bit(t *testing.T) {
	mem := newFakeMem()
	mem.put32(0x1000, 0x2000) // 4-byte pointer
	mem.put32(0x2004, 42)

	spec := chainSpec{Base: "0x1000", Offsets: []interface{}{"0x4"}, Type: "int32"}
	r := resolveChain(mem, spec, binary.LittleEndian, 4)
	if r.brokenAt >= 0 {
		t.Fatalf("unexpected broken: %s", r.brokenMsg)
	}
	if r.finalAddr != 0x2004 || r.valueStr != "42" {
		t.Fatalf("got final=0x%X value=%q, want 0x2004/42", r.finalAddr, r.valueStr)
	}
}

func TestParseFlatOffsets(t *testing.T) {
	cases := map[string]int{
		"0x10, 0x8, 0x0":       3,
		"[\"0x10\",\"0x8\"]":   2,
		"0x10 0x8":             2,
		"":                     0,
	}
	for in, want := range cases {
		got, err := parseFlatOffsets(in)
		if err != nil {
			t.Fatalf("parseFlatOffsets(%q) err: %v", in, err)
		}
		if len(got) != want {
			t.Fatalf("parseFlatOffsets(%q) len = %d, want %d", in, len(got), want)
		}
	}
}
