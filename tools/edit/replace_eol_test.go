package edit

import (
	"strings"
	"testing"
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

func TestReplaceMixedFileNoFalseMatch(t *testing.T) {
	res := Replace(mixedContent, "lfA\nNOPE", "x\ny", false, tabStyle, false)
	if res.Applied {
		t.Fatalf("absent anchor reported as replaced: %q", res.Content)
	}
}
