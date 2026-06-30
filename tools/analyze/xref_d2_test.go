package analyze

// xref guidance test on a real ordinal-only PE (D2Game.dll). Gated on
// AGENT_TOOL_D2_DIR (see exports_d2_test.go).

import (
	"path/filepath"
	"strings"
	"testing"
)

// The originally reported case: xref 0x6fc67be4 finds 0 direct references. Rather
// than a bare "No references found", the tool should point at the enclosing
// function start so the agent can re-query for the real callers.
func TestXrefZeroRefsGivesEnclosingHint(t *testing.T) {
	path := filepath.Join(d2Dir(t), "D2Game.dll")
	out, err := opXref(AnalyzeInput{Operation: "xref", FilePath: path, TargetVA: "0x6fc67be4"})
	if err != nil {
		t.Fatalf("xref: %v", err)
	}
	t.Logf("\n%s", out)
	if !strings.Contains(out, "No references found") {
		t.Skip("0x6fc67be4 unexpectedly has direct refs in this build of the DLL")
	}
	// Must offer an actionable next step instead of a bare dead end.
	if !strings.Contains(out, "Note:") {
		t.Errorf("expected a Note hint, got:\n%s", out)
	}
	actionable := strings.Contains(out, "target_va=") || strings.Contains(out, "no DIRECT callers") ||
		strings.Contains(out, "function_at") || strings.Contains(out, "disassemble")
	if !actionable {
		t.Errorf("hint lacks actionable guidance:\n%s", out)
	}
}

// A mid-function address inside a confidently-resolved function (0x6fc4e0d5 in
// the call target 0x6fc4e050) should, on 0 direct refs, point at that start.
func TestXrefMidFunctionPointsAtStart(t *testing.T) {
	path := filepath.Join(d2Dir(t), "D2Game.dll")
	out, err := opXref(AnalyzeInput{Operation: "xref", FilePath: path, TargetVA: "0x6fc4e0d5"})
	if err != nil {
		t.Fatalf("xref: %v", err)
	}
	if !strings.Contains(out, "No references found") {
		t.Skip("0x6fc4e0d5 unexpectedly has direct refs")
	}
	t.Logf("\n%s", out)
	if !strings.Contains(out, "inside function 0x6fc4e050") || !strings.Contains(out, "target_va=\"0x6fc4e050\"") {
		t.Errorf("expected a hint pointing at function start 0x6fc4e050, got:\n%s", out)
	}
}
