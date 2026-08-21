package common

import "strings"

// LineEndingCursor reports which newline form a byte span of a file belongs to.
//
// Files with a single newline form answer the same for every span, so callers
// can use this unconditionally. It exists for mixed files: a CRLF-era file with
// a later LF-only edit has regions of both, and inserting the file's dominant
// form into the minority region silently rewrites its newlines.
//
// Spans are expected in increasing order, which is how a splice walks a file.
// The lookahead for a line terminator then never rescans, so a whole edit costs
// one pass over the content no matter how many spans are queried. A span that
// moves backwards restarts the walk, which stays correct but pays for the
// rewind. Not safe for concurrent use.
type LineEndingCursor struct {
	content  string
	fallback string
	hasNL    bool

	// Terminator lookahead state. foundPos is the newline the last lookahead
	// stopped on, -1 once the scan proved there is none before EOF, and -2
	// before the first lookahead.
	scan      int
	foundPos  int
	foundKind string
	lastEnd   int

	// Newline ending the last terminated line, resolved on demand.
	finalKind string
	finalDone bool
}

// NewLineEndingCursor prepares a cursor over content.
func NewLineEndingCursor(content string) *LineEndingCursor {
	return &LineEndingCursor{
		content:  content,
		fallback: DetectLineEnding(content),
		hasNL:    strings.ContainsAny(content, "\r\n"),
		foundPos: -2,
	}
}

// At reports the newline form to use for text replacing content[start:end).
// Newlines inside the span decide by majority; a span with none inherits the
// newline that terminates its line, then the one that started it, and finally
// the fallback.
func (c *LineEndingCursor) At(start, end int) string {
	if !c.hasNL {
		return c.fallback
	}
	if start < 0 {
		start = 0
	}
	if end > len(c.content) {
		end = len(c.content)
	}
	if end < start {
		end = start
	}
	if end < c.lastEnd {
		c.scan, c.foundPos, c.foundKind = 0, -2, ""
	}
	c.lastEnd = end

	if kind := c.spanMajority(start, end); kind != "" {
		return kind
	}
	if kind := c.terminator(end); kind != "" {
		return kind
	}
	// No newline inside the span and none after it, so the span sits on the
	// last, unterminated line -- and the file's final newline is the one that
	// opened it.
	if kind := c.final(); kind != "" {
		return kind
	}
	return c.fallback
}

// spanMajority returns the dominant newline form inside [start,end), or "" when
// the span holds none.
func (c *LineEndingCursor) spanMajority(start, end int) string {
	var lf, crlf, cr int
	lfAt, crlfAt, crAt := 0, 0, 0
	for i := start; i < end; i++ {
		switch c.content[i] {
		case '\r':
			// Pair check runs against the whole content, not the span: a span
			// ending between CR and LF still sits in a CRLF region.
			if i+1 < len(c.content) && c.content[i+1] == '\n' {
				if crlf == 0 {
					crlfAt = i
				}
				crlf++
				i++
			} else {
				if cr == 0 {
					crAt = i
				}
				cr++
			}
		case '\n':
			// A span starting on the LF half of a CRLF still sits in a CRLF
			// region. Reaching here with a CR behind means that CR is outside
			// the span -- one inside would have been consumed by the case above,
			// which skips its LF.
			if i > 0 && c.content[i-1] == '\r' {
				if crlf == 0 {
					crlfAt = i - 1
				}
				crlf++
			} else {
				if lf == 0 {
					lfAt = i
				}
				lf++
			}
		}
	}
	if lf+crlf+cr == 0 {
		return ""
	}

	// Highest count wins. A tie goes to whichever tied form appears first, so
	// the region the span opens in keeps its own form -- seeding from the very
	// first newline instead would mis-resolve a tie that form is not part of.
	best, bestCount, bestAt := "", 0, 0
	for _, f := range []struct {
		ending string
		count  int
		at     int
	}{{"\r\n", crlf, crlfAt}, {"\n", lf, lfAt}, {"\r", cr, crAt}} {
		if f.count == 0 {
			continue
		}
		if f.count > bestCount || (f.count == bestCount && f.at < bestAt) {
			best, bestCount, bestAt = f.ending, f.count, f.at
		}
	}
	return best
}

// terminator returns the form of the first newline at or after end, or "" when
// none remains. The scan only moves forward across calls.
func (c *LineEndingCursor) terminator(end int) string {
	if c.foundPos == -1 {
		return "" // an earlier scan already reached EOF without a newline
	}
	// The cached hit is the first newline at or after an earlier, smaller end,
	// so nothing can sit between end and it. Comparing against the scan
	// position rather than the hit position also covers an empty span landing
	// between a CR and its LF -- that newline still terminates the span.
	if c.foundPos >= 0 && c.scan > end {
		return c.foundKind
	}
	i := end
	if c.scan > i {
		i = c.scan
	}
	for ; i < len(c.content); i++ {
		switch c.content[i] {
		case '\n':
			c.foundPos, c.foundKind, c.scan = i, "\n", i+1
			// Landing on the '\n' of a CRLF still reports CRLF.
			if i > 0 && c.content[i-1] == '\r' {
				c.foundKind = "\r\n"
			}
			return c.foundKind
		case '\r':
			c.foundPos = i
			if i+1 < len(c.content) && c.content[i+1] == '\n' {
				c.foundKind, c.scan = "\r\n", i+2
			} else {
				c.foundKind, c.scan = "\r", i+1
			}
			return c.foundKind
		}
	}
	c.foundPos, c.foundKind, c.scan = -1, "", len(c.content)
	return ""
}

// final returns the form of the last newline in the content, resolved once.
func (c *LineEndingCursor) final() string {
	if c.finalDone {
		return c.finalKind
	}
	c.finalDone = true
	for i := len(c.content) - 1; i >= 0; i-- {
		if c.content[i] == '\n' {
			c.finalKind = "\n"
			if i > 0 && c.content[i-1] == '\r' {
				c.finalKind = "\r\n"
			}
			break
		}
		if c.content[i] == '\r' {
			c.finalKind = "\r"
			break
		}
	}
	return c.finalKind
}

// LineEndingAround is the one-shot form of LineEndingCursor.At for callers with
// a single span to resolve.
func LineEndingAround(content string, start, end int, fallback string) string {
	c := NewLineEndingCursor(content)
	c.fallback = fallback
	return c.At(start, end)
}

// LineEndingMap is an LF-normalized view of content plus the offset map back to
// the original bytes.
//
// Matching a multi-line needle against raw content forces a choice of newline
// form, and any choice is wrong for a mixed file: normalizing the needle to the
// file's dominant form makes every minority-newline region unmatchable. Search
// the normalized view instead, then map the hit back to an exact byte span so
// untouched bytes -- newlines included -- are never rewritten.
//
// Not safe for concurrent use: offset translation keeps a cursor. Build one per
// edit.
type LineEndingMap struct {
	Original string // content as read
	Norm     string // Original with every CRLF and lone CR collapsed to LF
	Dominant string // dominant newline of the whole content

	region *LineEndingCursor
	// Offset translation walks Original forward instead of indexing every
	// newline: one int per CRLF costs hundreds of MB on a large CRLF file.
	// Splicing queries offsets in increasing order, so the walk is O(len)
	// across a whole edit; a query that moves backwards restarts it.
	curNorm, curOrig int
}

// NewLineEndingMap builds the normalized view of content.
func NewLineEndingMap(content string) *LineEndingMap {
	m := &LineEndingMap{
		Original: content,
		Norm:     content,
		Dominant: DetectLineEnding(content),
		region:   NewLineEndingCursor(content),
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
	return m.region.At(m.OrigOffset(start), m.OrigOffset(end))
}
