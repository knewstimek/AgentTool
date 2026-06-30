package analyze

import (
	"strings"
	"testing"
)

// The instruction cap must (a) limit output to `count` instructions, and
// (b) emit a truncation hint with a resume VA when it cuts mid-function -- but
// NOT when the disassembly ends naturally (data exhausted). Guards the
// pagination contract the agent relies on.
func TestDisasmTruncationHint(t *testing.T) {
	// 6x `nop` (0x90) then data continues -- decoding 2 must truncate with a hint.
	nops := []byte{0x90, 0x90, 0x90, 0x90, 0x90, 0x90}
	out, err := disasmX86Opts(nops, 0x401000, 0, 2, 32, nil, false)
	if err != nil {
		t.Fatalf("disasm: %v", err)
	}
	if strings.Count(out, "nop") != 2 {
		t.Errorf("expected exactly 2 instructions, got:\n%s", out)
	}
	if !strings.Contains(out, "truncated at the 2-instruction cap") {
		t.Errorf("expected truncation hint, got:\n%s", out)
	}
	// Resume VA = base + 2 consumed bytes (2 nops) = 0x401002.
	if !strings.Contains(out, "va=\"0x401002\"") {
		t.Errorf("expected resume va 0x401002, got:\n%s", out)
	}

	// Exactly enough data (2 nops): cap reached but nothing ahead -> no hint.
	twoNops := []byte{0x90, 0x90}
	out2, _ := disasmX86Opts(twoNops, 0x401000, 0, 2, 32, nil, false)
	if strings.Contains(out2, "truncated") {
		t.Errorf("no truncation hint expected when data is exhausted, got:\n%s", out2)
	}

	// stop_at_ret hitting a real boundary must not be flagged as truncated.
	// ret (C3) followed by int3 padding = confirmed boundary.
	retPad := []byte{0x90, 0xC3, 0xCC, 0xCC}
	out3, _ := disasmX86Opts(retPad, 0x401000, 0, 50, 32, nil, true)
	if !strings.Contains(out3, "stopped at function return") {
		t.Errorf("expected ret-stop, got:\n%s", out3)
	}
	if strings.Contains(out3, "truncated") {
		t.Errorf("ret-boundary must not be flagged truncated, got:\n%s", out3)
	}
}
