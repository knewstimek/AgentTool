package analyze

// Behavior tests for export-anchored function_at on a real ordinal-only PE
// (D2Game.dll). Gated on AGENT_TOOL_D2_DIR (see exports_d2_test.go).

import (
	"path/filepath"
	"strings"
	"testing"
)

func d2GamePath(t *testing.T) string {
	return filepath.Join(d2Dir(t), "D2Game.dll")
}

// The agent's original failure: function_at on 0x6fc6761d produced a misaligned
// start (0x6fc67515, inside a `mov edx, imm32` whose immediate contained a 0x90
// that the scan mistook for NOP padding). Call-target seeding now recovers the
// TRUE start at 0x6fc67450 (int3-padded, "sub esp" prologue, a direct-call
// target) at high confidence. The old wrong start must never reappear.
func TestFunctionAtResolvesPreviouslyMisaligned(t *testing.T) {
	path := d2GamePath(t)
	out, err := opFunctionAt(AnalyzeInput{Operation: "function_at", FilePath: path, VA: "0x6fc6761d"})
	if err != nil {
		t.Fatalf("function_at: %v", err)
	}
	t.Logf("\n%s", out)
	if strings.Contains(out, "0x6fc67515") {
		t.Errorf("the old misaligned start 0x6fc67515 reappeared:\n%s", out)
	}
	if !strings.Contains(out, "0x6fc67450") {
		t.Errorf("expected true start 0x6fc67450, got:\n%s", out)
	}
	// A discovered direct-call target is "call-target"/"high" -- never the
	// export-only "exact".
	if !strings.Contains(out, "start_source: call-target") {
		t.Errorf("expected start_source: call-target, got:\n%s", out)
	}
}

// function_at directly on an exported ordinal must resolve to that export with
// exact confidence and the ordinal label.
func TestFunctionAtExportIsExact(t *testing.T) {
	path := d2GamePath(t)
	// Ord 10000 -> RVA 0x2b840 -> VA 0x6fc4b840 (verified clean prologue).
	out, err := opFunctionAt(AnalyzeInput{Operation: "function_at", FilePath: path, VA: "0x6fc4b840"})
	if err != nil {
		t.Fatalf("function_at: %v", err)
	}
	t.Logf("\n%s", out)
	if !strings.Contains(out, "start_source: export") {
		t.Errorf("expected start_source: export, got:\n%s", out)
	}
	if !strings.Contains(out, "confidence:   exact") {
		t.Errorf("expected confidence: exact, got:\n%s", out)
	}
	if !strings.Contains(out, "Ordinal_10000") {
		t.Errorf("expected Ordinal_10000 label, got:\n%s", out)
	}
	if !strings.Contains(out, "0x6fc4b840") {
		t.Errorf("expected start VA 0x6fc4b840, got:\n%s", out)
	}
}

// Over-attribution guard: when a non-exported internal function sits between an
// export and the query, the export must NOT be claimed. 0x6fc4e0d5 lives in an
// internal function at 0x6fc4e050 (preceded by int3 padding at 0x6fc4e045..4f);
// the nearest export below it is Ord10024 @ 0x6fc4df10, which ends before the
// padding. The result must be the internal start, never "export (Ordinal_10024)".
func TestFunctionAtDoesNotOverAttributeToExport(t *testing.T) {
	path := d2GamePath(t)
	out, err := opFunctionAt(AnalyzeInput{Operation: "function_at", FilePath: path, VA: "0x6fc4e0d5"})
	if err != nil {
		t.Fatalf("function_at: %v", err)
	}
	t.Logf("\n%s", out)
	// Ord10024 ends before the int3 padding at 0x6fc4e045, so it must never be
	// claimed. Call-target seeding recovers the true internal start at 0x6fc4e050.
	if strings.Contains(out, "Ordinal_10024") || strings.Contains(out, "start_source: export") {
		t.Errorf("over-attributed internal function to export Ord10024:\n%s", out)
	}
	if !strings.Contains(out, "0x6fc4e050") {
		t.Errorf("expected internal start 0x6fc4e050, got:\n%s", out)
	}
	if !strings.Contains(out, "start_source: call-target") {
		t.Errorf("expected start_source: call-target, got:\n%s", out)
	}
}

// An address inside an exported function's body must anchor back to the export
// start (alignment validated), not to a heuristic guess.
func TestFunctionAtInsideExportAnchors(t *testing.T) {
	path := d2GamePath(t)
	// 0x6fc4b845 is inside Ord 10000 (start 0x6fc4b840): push ebx; mov ebx,...;
	// the query sits on the `push ebp` at +5.
	out, err := opFunctionAt(AnalyzeInput{Operation: "function_at", FilePath: path, VA: "0x6fc4b845"})
	if err != nil {
		t.Fatalf("function_at: %v", err)
	}
	t.Logf("\n%s", out)
	if !strings.Contains(out, "start_source: export") || !strings.Contains(out, "0x6fc4b840") {
		t.Errorf("expected anchor to export start 0x6fc4b840, got:\n%s", out)
	}
}
