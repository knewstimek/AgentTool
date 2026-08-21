package common

import (
	"sort"
	"strings"
)

// LineEndingAround reports which newline form the region covering [start,end)
// of content uses. Newlines inside the span decide by majority (ties go to the
// first one seen); a span with none inherits the newline that terminates its
// line, then the one that started it, and finally fallback.
//
// Files with a single newline form answer the same for every span, so callers
// can use this unconditionally. It exists for mixed files: a CVS-era CRLF file
// with a later LF-only edit has regions of both, and inserting the file's
// dominant form into the minority region silently rewrites its newlines.
func LineEndingAround(content string, start, end int, fallback string) string {
	if start < 0 {
		start = 0
	}
	if end > len(content) {
		end = len(content)
	}
	if end < start {
		end = start
	}

	var lf, crlf, cr int
	first := ""
	for i := start; i < end; i++ {
		switch content[i] {
		case '\r':
			// Pair check runs against the whole content, not the span: a span
			// ending between CR and LF still sits in a CRLF region.
			if i+1 < len(content) && content[i+1] == '\n' {
				crlf++
				i++
				if first == "" {
					first = "\r\n"
				}
			} else {
				cr++
				if first == "" {
					first = "\r"
				}
			}
		case '\n':
			lf++
			if first == "" {
				first = "\n"
			}
		}
	}
	if lf+crlf+cr > 0 {
		best, bestCount := first, 0
		for _, c := range []struct {
			ending string
			count  int
		}{{"\r\n", crlf}, {"\n", lf}, {"\r", cr}} {
			// Strict > keeps first on a tie: the span starts in that region.
			if c.count > bestCount {
				best, bestCount = c.ending, c.count
			}
		}
		if bestCount > 0 {
			return best
		}
	}

	// Newline that terminates the span's line. Landing on the '\n' of a CRLF
	// still reports CRLF thanks to the look-back.
	for i := end; i < len(content); i++ {
		if content[i] == '\n' {
			if i > 0 && content[i-1] == '\r' {
				return "\r\n"
			}
			return "\n"
		}
		if content[i] == '\r' {
			if i+1 < len(content) && content[i+1] == '\n' {
				return "\r\n"
			}
			return "\r"
		}
	}

	for i := start - 1; i >= 0; i-- {
		if content[i] == '\n' {
			if i > 0 && content[i-1] == '\r' {
				return "\r\n"
			}
			return "\n"
		}
		if content[i] == '\r' {
			return "\r"
		}
	}

	return fallback
}

// LineEndingMap is an LF-normalized view of content plus the offset map back to
// the original bytes.
//
// Matching a multi-line needle against raw content forces a choice of newline
// form, and any choice is wrong for a mixed file: normalizing the needle to the
// file's dominant form makes every minority-newline region unmatchable. Search
// the normalized view instead, then map the hit back to an exact byte span so
// untouched bytes -- newlines included -- are never rewritten.
type LineEndingMap struct {
	Original string // content as read
	Norm     string // Original with every CRLF and lone CR collapsed to LF
	Dominant string // dominant newline of the whole content
	crlfPos  []int  // Norm offsets of newlines that were CRLF in Original
}

// NewLineEndingMap builds the normalized view of content.
func NewLineEndingMap(content string) *LineEndingMap {
	m := &LineEndingMap{Original: content, Norm: content, Dominant: DetectLineEnding(content)}
	// No CR means Norm is already the content and offsets map one to one --
	// the common case, kept allocation-free.
	if !strings.ContainsRune(content, '\r') {
		return m
	}

	var sb strings.Builder
	sb.Grow(len(content))
	for i := 0; i < len(content); i++ {
		switch content[i] {
		case '\r':
			if i+1 < len(content) && content[i+1] == '\n' {
				m.crlfPos = append(m.crlfPos, sb.Len())
				i++
			}
			sb.WriteByte('\n')
		default:
			sb.WriteByte(content[i])
		}
	}
	m.Norm = sb.String()
	return m
}

// OrigOffset translates an offset in Norm to the matching offset in Original.
// Only CRLF shifts offsets (two bytes collapsed to one); a lone CR does not.
func (m *LineEndingMap) OrigOffset(norm int) int {
	if norm < 0 {
		norm = 0
	}
	if norm > len(m.Norm) {
		norm = len(m.Norm)
	}
	if len(m.crlfPos) == 0 {
		return norm
	}
	return norm + sort.SearchInts(m.crlfPos, norm)
}

// LocalLineEnding reports the newline form to use for text replacing the span
// [start,end) of Norm, so an edit inside a minority-newline region keeps that
// region's form instead of the file's dominant one.
func (m *LineEndingMap) LocalLineEnding(start, end int) string {
	return LineEndingAround(m.Original, m.OrigOffset(start), m.OrigOffset(end), m.Dominant)
}
