package analyze

// call_graph CFG-scan test on a real ordinal-only PE (D2Game.dll). Gated on
// AGENT_TOOL_D2_DIR (see exports_d2_test.go).

import (
	"path/filepath"
	"strings"
	"testing"
)

// Ord10008 (0x6fc4e1e0) calls the internal function 0x6fc4e050 (verified by
// disassembly: call at 0x6fc4e2db). CFG-based call scanning must surface that
// edge without leaking into neighbouring functions.
func TestCallGraphCFGScanFindsRealCallee(t *testing.T) {
	path := filepath.Join(d2Dir(t), "D2Game.dll")
	out, err := opCallGraph(AnalyzeInput{Operation: "call_graph", FilePath: path, VA: "0x6fc4e1e0", Count: 1})
	if err != nil {
		t.Fatalf("call_graph: %v", err)
	}
	t.Logf("\n%s", out)
	if !strings.Contains(out, "0x6fc4e050") {
		t.Errorf("expected callee 0x6fc4e050 in Ord10008's call graph, got:\n%s", out)
	}
}
