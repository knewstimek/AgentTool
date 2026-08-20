package common

import "testing"

func TestAnalyzeLineEndings(t *testing.T) {
	tests := []struct {
		name                  string
		content, kind, ending string
		crlf, lf, cr          int
	}{
		{"none", "one line", "None", "\n", 0, 0, 0},
		{"lf", "a\nb\n", "LF", "\n", 0, 2, 0},
		{"crlf", "a\r\nb\r\n", "CRLF", "\r\n", 2, 0, 0},
		{"mixed dominant crlf", "a\r\nb\r\nc\n", "Mixed", "\r\n", 2, 1, 0},
		{"mixed tie uses first", "a\nb\r\n", "Mixed", "\n", 1, 1, 0},
		{"bare cr", "a\rb\r", "CR", "\r", 0, 0, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeLineEndings(tt.content)
			if got.Kind != tt.kind || got.Dominant != tt.ending || got.CRLFCount != tt.crlf || got.LFCount != tt.lf || got.CRCount != tt.cr {
				t.Fatalf("AnalyzeLineEndings() = %+v", got)
			}
		})
	}
}

func TestNormalizeLineEndings(t *testing.T) {
	got := NormalizeLineEndings("a\r\nb\nc\rd", "\r\n")
	if got != "a\r\nb\r\nc\r\nd" {
		t.Fatalf("unexpected normalized text %q", got)
	}
}
