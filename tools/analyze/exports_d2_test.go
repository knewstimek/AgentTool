package analyze

// Regression coverage for ordinal-only PE export parsing (parseExports).
//
// Diablo II's D2*.dll export purely by ordinal (NumberOfNames == 0). The old
// name-table-driven parser returned nothing for them, denying function_at/xref/
// call_graph any export ground truth. These DLLs are proprietary and cannot be
// committed to a public repo, so the test is gated on AGENT_TOOL_D2_DIR and
// skips when unset (CI stays green; local runs verify against the real files).

import (
	"debug/pe"
	"os"
	"path/filepath"
	"testing"
)

func d2Dir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("AGENT_TOOL_D2_DIR")
	if dir == "" {
		t.Skip("AGENT_TOOL_D2_DIR not set -- skipping Diablo II ordinal-only export test")
	}
	return dir
}

func TestParseExportsOrdinalOnly(t *testing.T) {
	dir := d2Dir(t)

	// D2Common.dll exports hundreds of functions purely by ordinal.
	for _, name := range []string{"D2Common.dll", "D2Game.dll", "D2Client.dll"} {
		t.Run(name, func(t *testing.T) {
			f, err := pe.Open(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("open %s: %v", name, err)
			}
			defer f.Close()

			exports := parseExports(f)
			if len(exports) == 0 {
				t.Fatalf("%s: parseExports returned 0 entries (ordinal-only exports not parsed)", name)
			}

			named, ordinalOnly, forwarders := 0, 0, 0
			for _, e := range exports {
				switch {
				case e.forwarder:
					forwarders++
				case e.name != "":
					named++
				default:
					ordinalOnly++
				}
				if e.ordinal == 0 {
					t.Errorf("%s: export with rva 0x%x has ordinal 0 (Base not applied)", name, e.rva)
				}
			}
			// These DLLs are ordinal-only: the vast majority must be unnamed.
			if ordinalOnly == 0 {
				t.Errorf("%s: expected ordinal-only exports, got named=%d ordinalOnly=%d", name, named, ordinalOnly)
			}
			t.Logf("%s: %d exports (named=%d ordinalOnly=%d forwarders=%d)", name, len(exports), named, ordinalOnly, forwarders)
		})
	}
}
