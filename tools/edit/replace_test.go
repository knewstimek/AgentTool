package edit

import (
	"strings"
	"testing"
)

// ---- Pass 1: Direct match ----

func TestReplace_DirectMatch(t *testing.T) {
	content := "func main() {\n\tfmt.Println(\"hello\")\n}"
	result := Replace(content, "\"hello\"", "\"world\"", false, IndentStyle{UseTabs: true, IndentSize: 4}, false)

	if !result.Applied {
		t.Fatalf("expected match, got: %s", result.Message)
	}
	if result.MatchCount != 1 {
		t.Errorf("match count = %d, want 1", result.MatchCount)
	}
	want := "func main() {\n\tfmt.Println(\"world\")\n}"
	if result.Content != want {
		t.Errorf("got %q, want %q", result.Content, want)
	}
}

// ---- Pass 2/3/4: Spaces <-> Tabs conversion ----

func TestReplace_SpacesToTabsConversion(t *testing.T) {
	content := "func main() {\n\tfmt.Println(\"hello\")\n}"
	oldStr := "    fmt.Println(\"hello\")"
	newStr := "    fmt.Println(\"world\")"

	result := Replace(content, oldStr, newStr, false, IndentStyle{UseTabs: true, IndentSize: 4}, false)

	if !result.Applied {
		t.Fatalf("expected match after indent conversion, got: %s", result.Message)
	}
	want := "func main() {\n\tfmt.Println(\"world\")\n}"
	if result.Content != want {
		t.Errorf("got %q, want %q", result.Content, want)
	}
}

func TestReplace_Pass4_BruteForceIndentSize(t *testing.T) {
	// File uses tabs, old_string uses 2-space indent (not 4)
	content := "func foo() {\n\tif true {\n\t\tx := 1\n\t}\n}"
	oldStr := "  x := 1"
	newStr := "  x := 42"
	result := Replace(content, oldStr, newStr, false, IndentStyle{UseTabs: true, IndentSize: 4}, false)
	if !result.Applied {
		t.Fatalf("pass 4 brute force failed: %s", result.Message)
	}
	if !strings.Contains(result.Content, "\t\tx := 42") {
		t.Errorf("expected 2-tab x := 42, got:\n%s", result.Content)
	}
}

func TestReplace_Pass5_TabsToSpaces(t *testing.T) {
	// File uses 4-space indent, old_string has tabs
	content := "func foo() {\n    x := 1\n}"
	oldStr := "\tx := 1"
	newStr := "\tx := 42"
	result := Replace(content, oldStr, newStr, false, IndentStyle{UseTabs: false, IndentSize: 4}, false)
	if !result.Applied {
		t.Fatalf("pass 5 tabs->spaces failed: %s", result.Message)
	}
	if !strings.Contains(result.Content, "    x := 42") {
		t.Errorf("expected spaces x := 42, got:\n%s", result.Content)
	}
}

// ---- Pass 6: Tab depth normalization ----

func TestReplace_Pass6_TooShallow(t *testing.T) {
	// File has code at depth 3, agent provides old_string at depth 1
	content := "func foo() {\n\tif a {\n\t\tif b {\n\t\t\tx := 1\n\t\t\ty := 2\n\t\t}\n\t}\n}"
	// Agent says depth 1 but actual is depth 3
	oldStr := "\tx := 1\n\ty := 2"
	newStr := "\tx := 42\n\ty := 2"
	result := Replace(content, oldStr, newStr, false, IndentStyle{UseTabs: true, IndentSize: 4}, false)
	if !result.Applied {
		t.Fatalf("pass 6 shallow->deep failed: %s", result.Message)
	}
	if !strings.Contains(result.Content, "\t\t\tx := 42") {
		t.Errorf("expected depth-3 x := 42, got:\n%s", result.Content)
	}
}

func TestReplace_Pass6_TooDeep(t *testing.T) {
	// File has code at depth 1, agent provides old_string at depth 3
	content := "func foo() {\n\tx := 1\n\ty := 2\n}"
	// Agent says depth 3 but actual is depth 1
	oldStr := "\t\t\tx := 1\n\t\t\ty := 2"
	newStr := "\t\t\tx := 42\n\t\t\ty := 2"
	result := Replace(content, oldStr, newStr, false, IndentStyle{UseTabs: true, IndentSize: 4}, false)
	if !result.Applied {
		t.Fatalf("pass 6 deep->shallow failed: %s", result.Message)
	}
	if !strings.Contains(result.Content, "\tx := 42") {
		t.Errorf("expected depth-1 x := 42, got:\n%s", result.Content)
	}
	// Depth-3 should not appear
	if strings.Contains(result.Content, "\t\t\tx := 42") {
		t.Errorf("unexpected depth-3 replacement, got:\n%s", result.Content)
	}
}

func TestReplace_Pass6_TabDeltaPreserved(t *testing.T) {
	// old and new have different relative depths (tabDelta != 0)
	// File: old at depth 2. Agent: old at depth 1, new adds nesting (depth 2).
	// Expected: old found at depth 2, new placed at depth 2+1 = depth 3.
	content := "func foo() {\n\tif true {\n\t\tx := 1\n\t}\n}"
	oldStr := "\tx := 1"                         // agent says depth 1
	newStr := "\t\tif cond {\n\t\t\tx := 1\n\t\t}" // agent says depth 2-3 (tabDelta=+1)
	result := Replace(content, oldStr, newStr, false, IndentStyle{UseTabs: true, IndentSize: 4}, false)
	if !result.Applied {
		t.Fatalf("pass 6 tabDelta!=0 failed: %s", result.Message)
	}
	if !strings.Contains(result.Content, "\t\t\tif cond {") {
		t.Errorf("expected depth-3 if cond, got:\n%s", result.Content)
	}
}

func TestReplace_Pass6_TabDeltaNegative(t *testing.T) {
	// old deeper than new (removing nesting).
	// Agent: old at depth 2, new at depth 1 (tabDelta=-1).
	// File: old actually at depth 3. Expected: new at depth 2.
	content := "func foo() {\n\tif a {\n\t\tif b {\n\t\t\tx := 1\n\t\t}\n\t}\n}"
	oldStr := "\t\tx := 1" // agent says depth 2
	newStr := "\tx := 1"   // agent says depth 1 (removing 1 level)
	result := Replace(content, oldStr, newStr, false, IndentStyle{UseTabs: true, IndentSize: 4}, false)
	if !result.Applied {
		t.Fatalf("pass 6 tabDelta negative failed: %s", result.Message)
	}
	// old at actual depth 3, delta=-1, new should be at depth 2
	if !strings.Contains(result.Content, "\t\tx := 1") {
		t.Errorf("expected depth-2 x := 1, got:\n%s", result.Content)
	}
}

func TestReplace_Pass6_TabDeltaNegative_Clamp(t *testing.T) {
	// tabDelta extremely negative: new would go below depth 0, should clamp to 0.
	// old minTabsOld=3, new minTabsNew=0, tabDelta=-3.
	// File: old at depth 2. newDepth = 2+(-3) = -1 -> clamped to 0.
	content := "func foo() {\n\tif a {\n\t\t\tx := 1\n\t}\n}"
	oldStr := "\t\t\tx := 1" // depth 3 (agent)
	newStr := "x := 1"       // depth 0 (agent), tabDelta=-3
	result := Replace(content, oldStr, newStr, false, IndentStyle{UseTabs: true, IndentSize: 4}, false)
	if !result.Applied {
		t.Fatalf("pass 6 tabDelta clamp failed: %s", result.Message)
	}
	// newDepth clamped to 0, so x := 1 at top level
	if !strings.Contains(result.Content, "\nx := 1\n") && !strings.HasPrefix(result.Content, "x := 1\n") {
		t.Errorf("expected top-level x := 1, got:\n%q", result.Content)
	}
}

func TestReplace_Pass6_MultiCandidate_UniqueWins(t *testing.T) {
	// Use 2-line blocks to avoid substring contamination across depths.
	// Depth-1 block appears 3 times, depth-2 block appears once (unique).
	// Agent provides depth 3 (wrong). 6th pass should prefer depth 2 (count=1).
	content := strings.Join([]string{
		"\tx := 1\n\ty := 2", // depth 1, occurrence 1
		"\tx := 1\n\ty := 2", // depth 1, occurrence 2
		"\tx := 1\n\ty := 2", // depth 1, occurrence 3
		"\t\tx := 1\n\t\ty := 2", // depth 2, unique
	}, "\n")
	oldStr := "\t\t\tx := 1\n\t\t\ty := 2" // agent says depth 3
	newStr := "\t\t\tx := 99\n\t\t\ty := 2"
	result := Replace(content, oldStr, newStr, false, IndentStyle{UseTabs: true, IndentSize: 4}, false)
	if !result.Applied {
		t.Fatalf("pass 6 unique wins failed: %s", result.Message)
	}
	// Depth-2 occurrence replaced, depth-1 occurrences unchanged
	if !strings.Contains(result.Content, "\t\tx := 99\n\t\ty := 2") {
		t.Errorf("expected depth-2 replaced, got:\n%s", result.Content)
	}
	if strings.Count(result.Content, "x := 1") != 3 {
		t.Errorf("expected 3 unreplaced depth-1 x := 1, got:\n%s", result.Content)
	}
}

func TestReplace_Pass6_MultiCandidate_ClosestDepthWins(t *testing.T) {
	// Two unique 2-line blocks: depth 1 and depth 5.
	// Agent provides depth 2. absDist(1,2)=1 < absDist(5,2)=3 -> depth 1 wins.
	content := "\tbegin_block\n\tend_block\n\t\t\t\t\tbegin_block\n\t\t\t\t\tend_block"
	oldStr := "\t\tbegin_block\n\t\tend_block" // agent says depth 2
	newStr := "\t\tX_block\n\t\tY_block"
	result := Replace(content, oldStr, newStr, false, IndentStyle{UseTabs: true, IndentSize: 4}, false)
	if !result.Applied {
		t.Fatalf("pass 6 closest depth wins failed: %s", result.Message)
	}
	// Depth-1 block replaced (closer to 2), depth-5 unchanged
	if !strings.Contains(result.Content, "\tX_block") {
		t.Errorf("expected depth-1 block replaced, got:\n%s", result.Content)
	}
	if !strings.Contains(result.Content, "\t\t\t\t\tbegin_block") {
		t.Errorf("expected depth-5 block untouched, got:\n%s", result.Content)
	}
}

func TestReplace_Pass6_CRLF(t *testing.T) {
	// CRLF file: old_string at wrong tab depth should still be corrected
	content := "func foo() {\r\n\tif true {\r\n\t\tx := 1\r\n\t}\r\n}"
	// Agent provides depth 1, actual is depth 2
	oldStr := "\tx := 1"
	newStr := "\tx := 42"
	result := Replace(content, oldStr, newStr, false, IndentStyle{UseTabs: true, IndentSize: 4}, false)
	if !result.Applied {
		t.Fatalf("pass 6 CRLF failed: %s", result.Message)
	}
	if !strings.Contains(result.Content, "\r\n") {
		t.Errorf("CRLF not preserved in output")
	}
	if !strings.Contains(result.Content, "\t\tx := 42") {
		t.Errorf("expected depth-2 x := 42, got:\n%q", result.Content)
	}
}

func TestReplace_Pass6_ReplaceAll(t *testing.T) {
	// replaceAll=true with 6th pass: two identical blocks at depth 2, agent says depth 1
	content := "\t\tx := 1\n\t\ty := 2\n\t\tx := 1\n\t\ty := 2"
	oldStr := "\tx := 1\n\ty := 2" // depth 1 (wrong)
	newStr := "\tx := 99\n\ty := 2"
	result := Replace(content, oldStr, newStr, true, IndentStyle{UseTabs: true, IndentSize: 4}, false)
	if !result.Applied {
		t.Fatalf("pass 6 replaceAll failed: %s", result.Message)
	}
	count := strings.Count(result.Content, "\t\tx := 99")
	if count != 2 {
		t.Errorf("expected 2 replacements at depth 2, got %d, content:\n%s", count, result.Content)
	}
}

func TestReplace_Pass6_MultiLineBlock(t *testing.T) {
	// Multi-line block at wrong depth
	content := "package main\n\nfunc foo() {\n\tif cond {\n\t\ta := 1\n\t\tb := 2\n\t\treturn a + b\n\t}\n}"
	// Agent provides the if-body at depth 1 (off by 1)
	oldStr := "\ta := 1\n\tb := 2\n\treturn a + b"
	newStr := "\ta := 10\n\tb := 20\n\treturn a + b"
	result := Replace(content, oldStr, newStr, false, IndentStyle{UseTabs: true, IndentSize: 4}, false)
	if !result.Applied {
		t.Fatalf("pass 6 multi-line failed: %s", result.Message)
	}
	if !strings.Contains(result.Content, "\t\ta := 10") {
		t.Errorf("expected depth-2 a := 10, got:\n%s", result.Content)
	}
}

// ---- Pass 7: Diagnostic ----

func TestReplace_Pass7_Diagnostic(t *testing.T) {
	// Mixed indentation in old_string (tab + spaces) can't be fixed by passes 1-6.
	// 7th pass detects the content exists with different indentation.
	content := "func foo() {\n\t\tx := 1\n}"
	// Mixed: 1 tab + 1 space (not a valid tab-only indent)
	oldStr := "\t x := 1"
	newStr := "\t x := 42"
	result := Replace(content, oldStr, newStr, false, IndentStyle{UseTabs: true, IndentSize: 4}, false)
	if result.Applied {
		t.Errorf("should not apply for mixed indentation, got: %q", result.Content)
	}
	if !strings.Contains(result.Message, "indentation differs") {
		t.Errorf("expected indentation diagnostic, got: %s", result.Message)
	}
}

// ---- Basic error cases ----

func TestReplace_NotFound(t *testing.T) {
	content := "func main() {}"
	result := Replace(content, "nonexistent", "replacement", false, IndentStyle{UseTabs: false, IndentSize: 4}, false)

	if result.Applied {
		t.Error("expected no match")
	}
	if result.Message != "old_string not found in file" {
		t.Errorf("unexpected message: %s", result.Message)
	}
}

func TestReplace_MultipleMatches_NoReplaceAll(t *testing.T) {
	content := "a = 1\nb = 1\nc = 1"
	result := Replace(content, "1", "2", false, IndentStyle{UseTabs: false, IndentSize: 4}, false)

	if result.Applied {
		t.Error("should fail with multiple matches when replace_all=false")
	}
}

func TestReplace_MultipleMatches_ReplaceAll(t *testing.T) {
	content := "a = 1\nb = 1\nc = 1"
	result := Replace(content, "1", "2", true, IndentStyle{UseTabs: false, IndentSize: 4}, false)

	if !result.Applied {
		t.Fatalf("expected match with replace_all=true, got: %s", result.Message)
	}
	want := "a = 2\nb = 2\nc = 2"
	if result.Content != want {
		t.Errorf("got %q, want %q", result.Content, want)
	}
}

func TestReplace_LineEndingPreservation(t *testing.T) {
	content := "line1\r\nline2\r\nline3"
	result := Replace(content, "line2", "replaced", false, IndentStyle{UseTabs: false, IndentSize: 4}, false)

	if !result.Applied {
		t.Fatalf("expected match, got: %s", result.Message)
	}
	want := "line1\r\nreplaced\r\nline3"
	if result.Content != want {
		t.Errorf("got %q, want %q", result.Content, want)
	}
}

// ---- shiftTabs unit tests ----

func TestShiftTabs_Add(t *testing.T) {
	s := "a\n\tb"
	got := shiftTabs(s, 2)
	want := "\t\ta\n\t\t\tb"
	if got != want {
		t.Errorf("shiftTabs add: got %q, want %q", got, want)
	}
}

func TestShiftTabs_Remove(t *testing.T) {
	s := "\t\ta\n\t\t\tb"
	got := shiftTabs(s, -2)
	want := "a\n\tb"
	if got != want {
		t.Errorf("shiftTabs remove: got %q, want %q", got, want)
	}
}

func TestShiftTabs_RemoveClamp(t *testing.T) {
	// Remove more tabs than present: clamp to 0, no negative
	s := "\ta\nb"
	got := shiftTabs(s, -5)
	want := "a\nb"
	if got != want {
		t.Errorf("shiftTabs clamp: got %q, want %q", got, want)
	}
}

func TestShiftTabs_Zero(t *testing.T) {
	s := "\ta\n\tb"
	got := shiftTabs(s, 0)
	if got != s {
		t.Errorf("shiftTabs zero: got %q, want %q", got, s)
	}
}

// ---- findMinLeadingTabs unit tests ----

func TestFindMinLeadingTabs_Basic(t *testing.T) {
	s := "\t\ta\n\t\t\tb\n\t\tc"
	got := findMinLeadingTabs(s)
	if got != 2 {
		t.Errorf("got %d, want 2", got)
	}
}

func TestFindMinLeadingTabs_EmptyLinesIgnored(t *testing.T) {
	s := "\t\ta\n\n\t\t\tb"
	got := findMinLeadingTabs(s)
	if got != 2 {
		t.Errorf("empty lines should be ignored, got %d, want 2", got)
	}
}

func TestFindMinLeadingTabs_NoTabs(t *testing.T) {
	s := "a\nb"
	got := findMinLeadingTabs(s)
	if got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}
