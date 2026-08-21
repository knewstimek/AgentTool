package edit

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

var tabStyle = IndentStyle{UseTabs: true, IndentSize: 4}

// mixedContent models the real-world case: a CRLF-dominant file that later got
// an LF-only edit, leaving a minority LF region inside it.
const mixedContent = "line1\r\nline2\r\nline3\r\nline4\r\n" +
	"lfA\nlfB\nlfC\n" +
	"line5\r\nline6\r\n"

func TestReplaceMinorityLFRegionMultiline(t *testing.T) {
	res := Replace(mixedContent, "lfA\nlfB", "lfX\nlfY", false, tabStyle, false)
	if !res.Applied {
		t.Fatalf("multiline anchor in minority-LF region not matched: %s", res.Message)
	}
	if !strings.Contains(res.Content, "lfX\nlfY\nlfC\n") {
		t.Fatalf("inserted lines did not keep the region's LF endings: %q", res.Content)
	}
	if strings.Contains(res.Content, "lfX\r\n") {
		t.Fatalf("inserted lines were forced to CRLF: %q", res.Content)
	}
	// Everything outside the edited span must be byte-identical.
	if !strings.HasPrefix(res.Content, "line1\r\nline2\r\nline3\r\nline4\r\n") ||
		!strings.HasSuffix(res.Content, "\nline5\r\nline6\r\n") {
		t.Fatalf("untouched CRLF regions were rewritten: %q", res.Content)
	}
}

func TestReplaceMinorityLFRegionSingleLine(t *testing.T) {
	// A single-line anchor has no newline to normalize, so it matched even before
	// the fix; it is kept as the control for the byte-mapping path.
	res := Replace(mixedContent, "lfB", "lfZ", false, tabStyle, false)
	if !res.Applied {
		t.Fatalf("single-line anchor in minority-LF region not matched: %s", res.Message)
	}
	if !strings.Contains(res.Content, "lfA\nlfZ\nlfC\n") {
		t.Fatalf("replacement landed wrong: %q", res.Content)
	}
}

func TestReplaceDominantCRLFRegionMultiline(t *testing.T) {
	res := Replace(mixedContent, "line2\nline3", "line2\nlineX", false, tabStyle, false)
	if !res.Applied {
		t.Fatalf("multiline anchor in dominant-CRLF region not matched: %s", res.Message)
	}
	if !strings.Contains(res.Content, "line2\r\nlineX\r\n") {
		t.Fatalf("inserted lines did not keep CRLF: %q", res.Content)
	}
	if !strings.Contains(res.Content, "lfA\nlfB\nlfC\n") {
		t.Fatalf("untouched LF region was rewritten: %q", res.Content)
	}
}

// New text inserted by one replace_all call must follow whichever region each
// individual hit landed in, not a single file-wide choice.
func TestReplaceAllPerRegionLineEndings(t *testing.T) {
	content := "a\r\nTARGET\r\nb\r\nc\nTARGET\nd\n"
	res := Replace(content, "TARGET", "X\nY", true, tabStyle, false)
	if !res.Applied || res.MatchCount != 2 {
		t.Fatalf("replace_all failed: applied=%v count=%d msg=%s", res.Applied, res.MatchCount, res.Message)
	}
	want := "a\r\nX\r\nY\r\nb\r\nc\nX\nY\nd\n"
	if res.Content != want {
		t.Fatalf("per-region line endings wrong:\n got %q\nwant %q", res.Content, want)
	}
}

// An anchor covering the seam between a CRLF region and an LF region has no
// single correct newline form; it must still match.
func TestReplaceAnchorStraddlingRegions(t *testing.T) {
	content := "head\r\nLAST\r\nfirstLF\nnext\n"
	res := Replace(content, "LAST\nfirstLF", "LAST\nchanged", false, tabStyle, false)
	if !res.Applied {
		t.Fatalf("anchor across the CRLF/LF seam not matched: %s", res.Message)
	}
	if !strings.HasPrefix(res.Content, "head\r\n") || !strings.HasSuffix(res.Content, "\nnext\n") {
		t.Fatalf("surrounding regions damaged: %q", res.Content)
	}
}

// Classic-Mac CR-only files: the agent still sends LF in old_string.
func TestReplaceCROnlyFile(t *testing.T) {
	res := Replace("a\rb\rc\r", "a\nb", "a\nB2", false, tabStyle, false)
	if !res.Applied {
		t.Fatalf("multiline anchor in CR-only file not matched: %s", res.Message)
	}
	if res.Content != "a\rB2\rc\r" {
		t.Fatalf("CR endings not preserved: %q", res.Content)
	}
}

// Indent-conversion passes run on the normalized view too, so they must keep
// working on a CRLF file.
func TestReplaceIndentConversionOnCRLF(t *testing.T) {
	content := "func f() {\r\n\t\tif x {\r\n\t\t\treturn 1\r\n\t\t}\r\n}\r\n"
	// old_string uses spaces where the file uses tabs, plus LF newlines.
	res := Replace(content, "        if x {\n            return 1\n        }", "\t\tif y {\n\t\t\treturn 2\n\t\t}", false, tabStyle, false)
	if !res.Applied {
		t.Fatalf("space->tab conversion on a CRLF file failed: %s", res.Message)
	}
	if res.Content != "func f() {\r\n\t\tif y {\r\n\t\t\treturn 2\r\n\t\t}\r\n}\r\n" {
		t.Fatalf("CRLF not preserved through indent conversion: %q", res.Content)
	}
}

// An anchor covering one LF and one CRLF is a tie; the region the span starts
// in wins, so the LF region is not converted to CRLF.
func TestReplaceTieKeepsTheRegionTheSpanStartsIn(t *testing.T) {
	res := Replace("a\nb\r\nc", "a\nb\n", "x\ny\n", false, tabStyle, false)
	if !res.Applied {
		t.Fatalf("not applied: %s", res.Message)
	}
	if res.Content != "x\ny\nc" {
		t.Fatalf("tie resolved wrong: %q, want %q", res.Content, "x\ny\nc")
	}
}

// A short old_string matching a large file must be rejected as ambiguous
// without first materializing one offset per hit.
func TestReplaceAmbiguousLargeFileStaysCheap(t *testing.T) {
	content := strings.Repeat("a", 2_000_000)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	res := Replace(content, "a", "b", false, tabStyle, false)
	runtime.ReadMemStats(&after)
	if res.Applied {
		t.Fatal("2 million matches should be rejected as ambiguous")
	}
	if !strings.Contains(res.Message, "2000000 times") {
		t.Fatalf("unexpected message: %s", res.Message)
	}
	// Collecting offsets first would allocate ~16 MB here.
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 4<<20 {
		t.Fatalf("rejecting an ambiguous edit allocated %d bytes", allocated)
	}
}

// A file with no newline at all must not be scanned for a neighbouring newline
// on every match; that turns replace_all quadratic.
func TestReplaceAllOnNewlineFreeFile(t *testing.T) {
	const n = 300_000
	start := time.Now()
	res := Replace(strings.Repeat("x", n), "x", "y\nz", true, tabStyle, false)
	elapsed := time.Since(start)
	if !res.Applied || res.MatchCount != n {
		t.Fatalf("applied=%v count=%d msg=%s", res.Applied, res.MatchCount, res.Message)
	}
	if len(res.Content) != n*3 || !strings.HasPrefix(res.Content, "y\nzy\nz") {
		t.Fatalf("unexpected content length %d", len(res.Content))
	}
	// Scanning per match would be ~9e10 byte reads here; the bound is loose
	// enough for a slow machine and still orders of magnitude below that.
	if elapsed > 10*time.Second {
		t.Fatalf("replace_all on a newline-free file took %s", elapsed)
	}
}

// A three-way tie inside the span goes to the form that appears first among the
// tied ones. The first newline overall (LF here) belongs to a losing form.
func TestReplaceTieAmongMajorityForms(t *testing.T) {
	res := Replace("a\nb\rc\r\nd\re\r\n", "a\nb\nc\nd\ne\n", "x\ny\n", false, tabStyle, false)
	if !res.Applied {
		t.Fatalf("not applied: %s", res.Message)
	}
	if res.Content != "x\ry\r" {
		t.Fatalf("tied majority resolved wrong: %q, want %q", res.Content, "x\ry\r")
	}
}

// Offset translation must not index every CRLF: that allocation dwarfs the file
// on a CRLF-dense one.
func TestReplaceOnCRLFDenseFileStaysCheap(t *testing.T) {
	content := strings.Repeat("\r\n", 400_000) + "MARK\r\n"
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	res := Replace(content, "MARK", "DONE", false, tabStyle, false)
	runtime.ReadMemStats(&after)
	if !res.Applied || !strings.HasSuffix(res.Content, "DONE\r\n") {
		t.Fatalf("applied=%v msg=%s", res.Applied, res.Message)
	}
	// One int per CRLF would add 3.2 MB on its own here.
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 3<<20 {
		t.Fatalf("editing a CRLF-dense file allocated %d bytes", allocated)
	}
}

func TestReplaceMixedFileNoFalseMatch(t *testing.T) {
	res := Replace(mixedContent, "lfA\nNOPE", "x\ny", false, tabStyle, false)
	if res.Applied {
		t.Fatalf("absent anchor reported as replaced: %q", res.Content)
	}
}
