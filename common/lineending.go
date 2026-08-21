package common

import "strings"

// localScanLimit bounds how far LineEndingAround looks for a neighbouring
// newline before falling back. 8 KiB covers any real source line.
const localScanLimit = 8 << 10

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
		// Seeded with the first ending seen and its own count, so an exact tie
		// keeps it -- the span starts in that region. Seeding the count at 0
		// instead would hand every tie to whichever candidate is checked first.
		best := first
		var bestCount int
		switch first {
		case "\r\n":
			bestCount = crlf
		case "\n":
			bestCount = lf
		case "\r":
			bestCount = cr
		}
		for _, c := range []struct {
			ending string
			count  int
		}{{"\r\n", crlf}, {"\n", lf}, {"\r", cr}} {
			if c.count > bestCount {
				best, bestCount = c.ending, c.count
			}
		}
		return best
	}

	// Newline that terminates the span's line. Landing on the '\n' of a CRLF
	// still reports CRLF thanks to the look-back. The lookaround is bounded:
	// past this distance "the local region" means nothing, and an unbounded
	// scan turns a many-match run on a minified file quadratic.
	forward := end + localScanLimit
	if forward > len(content) {
		forward = len(content)
	}
	for i := end; i < forward; i++ {
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

	backward := start - localScanLimit
	if backward < 0 {
		backward = 0
	}
	for i := start - 1; i >= backward; i-- {
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
// A LineEndingMap is not safe for concurrent use: offset translation keeps a
// cursor. Build one per edit.
type LineEndingMap struct {
	Original string // content as read
	Norm     string // Original with every CRLF and lone CR collapsed to LF
	Dominant string // dominant newline of the whole content

	hasNewline bool
	// Offset translation walks Original forward instead of indexing every
	// newline: one int per CRLF costs hundreds of MB on a large CRLF file.
	// Splicing queries offsets in increasing order, so the walk is O(len)
	// across a whole edit; a query that moves backwards restarts it.
	curNorm, curOrig int
}

// NewLineEndingMap builds the normalized view of content.
func NewLineEndingMap(content string) *LineEndingMap {
	m := &LineEndingMap{
		Original:   content,
		Norm:       content,
		Dominant:   DetectLineEnding(content),
		hasNewline: strings.ContainsAny(content, "\r\n"),
	}
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
	// Equal lengths mean nothing was collapsed, so offsets are identical.
	if len(m.Norm) == len(m.Original) {
		return norm
	}
	if norm < m.curNorm {
		m.curNorm, m.curOrig = 0, 0
	}
	for m.curNorm < norm {
		if m.Original[m.curOrig] == '\r' && m.curOrig+1 < len(m.Original) && m.Original[m.curOrig+1] == '\n' {
			m.curOrig += 2
		} else {
			m.curOrig++
		}
		m.curNorm++
	}
	return m.curOrig
}

// LocalLineEnding reports the newline form to use for text replacing the span
// [start,end) of Norm, so an edit inside a minority-newline region keeps that
// region's form instead of the file's dominant one.
func (m *LineEndingMap) LocalLineEnding(start, end int) string {
	// A file without a single newline has no regions to respect, and scanning
	// one for every match is what makes minified files pathological.
	if !m.hasNewline {
		return m.Dominant
	}
	return LineEndingAround(m.Original, m.OrigOffset(start), m.OrigOffset(end), m.Dominant)
}
