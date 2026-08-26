// Package textdiff provides line-oriented unified diffs shared by file tools.
package textdiff

import (
	"fmt"
	"strings"

	"github.com/pmezard/go-difflib/difflib"
)

// SplitLines splits text into lines after normalizing CRLF terminators. A
// trailing terminator does not create a synthetic empty line.
func SplitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// Unified returns a unified diff for two line sequences. SequenceMatcher uses
// stable inner anchors throughout large files, so sparse edits remain separate
// hunks instead of turning the whole span between the first and last edit into
// one replacement.
func Unified(nameA, nameB string, a, b []string, contextLines int) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("--- %s\n+++ %s\n", nameA, nameB))

	matcher := difflib.NewMatcher(a, b)
	for _, group := range matcher.GetGroupedOpCodes(contextLines) {
		first, last := group[0], group[len(group)-1]
		sb.WriteString(fmt.Sprintf("@@ -%s +%s @@\n",
			formatRange(first.I1, last.I2),
			formatRange(first.J1, last.J2)))

		for _, op := range group {
			switch op.Tag {
			case 'e':
				writeLines(&sb, ' ', a[op.I1:op.I2])
			case 'd':
				writeLines(&sb, '-', a[op.I1:op.I2])
			case 'i':
				writeLines(&sb, '+', b[op.J1:op.J2])
			case 'r':
				writeLines(&sb, '-', a[op.I1:op.I2])
				writeLines(&sb, '+', b[op.J1:op.J2])
			}
		}
	}

	return sb.String()
}

func formatRange(start, stop int) string {
	count := stop - start
	line := start + 1
	if count == 0 {
		line = start
	}
	return fmt.Sprintf("%d,%d", line, count)
}

// UnifiedStrings is the string-oriented form used by edit previews.
func UnifiedStrings(nameA, nameB, before, after string, contextLines int) string {
	return Unified(nameA, nameB, SplitLines(before), SplitLines(after), contextLines)
}

func writeLines(sb *strings.Builder, prefix byte, lines []string) {
	for _, line := range lines {
		sb.WriteByte(prefix)
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
}
