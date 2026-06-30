package analyze

// Gated on AGENT_TOOL_D2_DIR. Verifies that an internal function that the
// call-graph/sweep discovery does NOT anchor (its callers are themselves
// unreached, so it never becomes a call-target) but whose body starts with a
// recognized x86 entry idiom now resolves at medium/prologue instead of low.
// These three D2Common functions start with `mov eax,[esp+N]` (frameless leaf),
// sit right after an int3 padding run, and were confirmed unreachable from the
// discovery seeds -- the exact case the expanded strongPrologue improves.

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestFunctionAtInternalPrologueIsMedium(t *testing.T) {
	path := filepath.Join(d2Dir(t), "D2Common.dll")
	// query VA (inside the function) -> expected start VA.
	cases := map[string]string{
		"0x6fd56c24": "0x6fd56c20", // 8b 44 24 0c  mov eax,[esp+0xc]
		"0x6fd6e6d4": "0x6fd6e6d0", // 8b 44 24 04  mov eax,[esp+4]
		"0x6fd84084": "0x6fd84080", // 8b 44 24 04  mov eax,[esp+4]
	}
	for query, wantStart := range cases {
		out, err := opFunctionAt(AnalyzeInput{Operation: "function_at", FilePath: path, VA: query})
		if err != nil {
			t.Errorf("%s: %v", query, err)
			continue
		}
		if !strings.Contains(out, "Start:  "+wantStart) {
			t.Errorf("%s: expected start %s, got:\n%s", query, wantStart, out)
		}
		// The improvement: medium/prologue, never the old low/heuristic. (If a
		// future discovery pass anchors these as call-targets it would upgrade to
		// high -- acceptable, but update this test deliberately when that happens.)
		if !strings.Contains(out, "start_source: prologue") || !strings.Contains(out, "confidence:   medium") {
			t.Errorf("%s: expected prologue/medium, got:\n%s", query, out)
		}
		if strings.Contains(out, "confidence:   low") {
			t.Errorf("%s: regressed to low confidence:\n%s", query, out)
		}
	}
}

// The trust guard for the prologue expansion: a strong-prologue byte sequence
// that sits INSIDE a known function (a block the CFG proof couldn't reach via a
// jump table / indirect branch, with no int3 padding gap separating it from the
// enclosing start) must NOT be reported at medium. The int3-run boundary gate in
// refineFuncStart demotes it to low. Without the gate these queries returned a
// confident-wrong mid-function start -- the exact failure class this module
// guards against. Measured on the D2 corpus, the gate removes ~99.7% of such
// mid-function medium mislabels while keeping every int3-padded real start.
func TestFunctionAtMidFunctionPrologueNotMedium(t *testing.T) {
	path := filepath.Join(d2Dir(t), "D2Game.dll")
	// These queries fall inside functions whose start is CFG-unreachable from the
	// query (jump tables), so findPrologueBackward stops at a mid-function prologue
	// (0x6fc2359f = `56 8b f1`, 0x6fc235bb = `55 8b ec`) with no int3 gap above it.
	for _, query := range []string{"0x6fc235a0", "0x6fc235bb"} {
		out, err := opFunctionAt(AnalyzeInput{Operation: "function_at", FilePath: path, VA: query})
		if err != nil {
			t.Errorf("%s: %v", query, err)
			continue
		}
		// The invariant: never a confident-wrong mid-function medium. (low is the
		// honest answer here; a future discovery pass could instead anchor it as
		// call-target/high -- also acceptable. Only medium would be the bug.)
		if strings.Contains(out, "start_source: prologue") && strings.Contains(out, "confidence:   medium") {
			t.Errorf("%s: mid-function prologue reported at medium (gate failed):\n%s", query, out)
		}
	}
}
