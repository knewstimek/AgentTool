package analyze

import "testing"

// Pins the x86 entry idioms strongPrologue accepts at medium confidence. These
// were derived by measuring genuine function starts in the Diablo II DLLs and
// cross-checked against Ghidra's x86win_patterns.xml (see x86StrongIdioms). The
// test is NOT gated on the D2 corpus so it guards the classifier in CI.
func TestStrongPrologueX86Idioms(t *testing.T) {
	// Each case is the first bytes of a function; want=true means "medium".
	medium := []struct {
		name  string
		bytes []byte
	}{
		{"frame 55 8b ec", []byte{0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10}},
		{"sub esp 83 ec", []byte{0x83, 0xEC, 0x1C, 0x53}},
		{"sub esp 81 ec", []byte{0x81, 0xEC, 0x80, 0x00, 0x00, 0x00}},
		{"hotpatch 8bff558bec", []byte{0x8B, 0xFF, 0x55, 0x8B, 0xEC}},
		{"gcc frame 55 89 e5", []byte{0x55, 0x89, 0xE5, 0x83, 0xEC, 0x08}},
		{"thiscall 56 8b f1", []byte{0x56, 0x8B, 0xF1, 0x8B, 0x46, 0x04}},
		{"ebp-scratch 55 8b 6c 24", []byte{0x55, 0x8B, 0x6C, 0x24, 0x08}},
		{"3 callee push 53 56 57", []byte{0x53, 0x56, 0x57, 0x8B, 0x7C, 0x24}},
		{"frameless leaf 8b 44 24", []byte{0x8B, 0x44, 0x24, 0x04, 0x85, 0xC0}},
	}
	for _, c := range medium {
		if !strongPrologue(c.bytes, 0, 32) {
			t.Errorf("%s: expected strongPrologue=true (medium), got false", c.name)
		}
	}

	// Bare single-byte pushes stay weak (low) -- they appear mid-function too often
	// to justify medium. This is the line the advisor drew; it must not move.
	weak := []struct {
		name  string
		bytes []byte
	}{
		{"bare push ebx 53", []byte{0x53, 0x8B, 0x01}},     // push ebx; mov eax,[ecx] -- ambiguous
		{"bare push esi 56", []byte{0x56, 0xE8, 0x00, 0x00}}, // push esi; call -- arg push, not entry
		{"bare push edi 57", []byte{0x57, 0xFF, 0x15}},     // push edi; call [import] -- arg push
		{"mov eax,[abs] a1", []byte{0xA1, 0x00, 0x10, 0x40, 0x00}},
	}
	for _, c := range weak {
		if strongPrologue(c.bytes, 0, 32) {
			t.Errorf("%s: expected strongPrologue=false (low), got true", c.name)
		}
	}

	// The x86 idioms must NOT fire in x64 mode (a stripped x64 PE would otherwise
	// be mislabeled). x64 uses .pdata and never reaches this path in practice.
	x64only := [][]byte{
		{0x8B, 0xFF, 0x55, 0x8B, 0xEC}, // hotpatch is 32-bit
		{0x56, 0x8B, 0xF1},             // thiscall save-this is 32-bit
		{0x8B, 0x44, 0x24, 0x04},       // frameless leaf is 32-bit
		{0x55, 0x89, 0xE5},             // gcc x86 frame
	}
	for i, b := range x64only {
		if strongPrologue(b, 0, 64) {
			t.Errorf("x64only[%d]: x86 idiom fired in mode 64", i)
		}
	}

	// Shared multi-byte frames still work in x64 (these live in prologuePatterns).
	x64frames := [][]byte{
		{0x55, 0x48, 0x89, 0xE5},       // push rbp; mov rbp,rsp
		{0x48, 0x83, 0xEC, 0x28},       // sub rsp, imm8
		{0x40, 0x53},                   // push rbx (REX)
	}
	for i, b := range x64frames {
		if !strongPrologue(b, 0, 64) {
			t.Errorf("x64frames[%d]: expected medium in mode 64, got false", i)
		}
	}
}
