package edit

import (
	"fmt"
	"strings"

	"agent-tool/common"
)

// ReplaceResult holds the result of a replacement operation.
type ReplaceResult struct {
	Content    string
	MatchCount int
	Applied    bool
	Message    string
}

// Replace replaces oldStr with newStr in content.
// Attempts automatic conversion to match the file's indentation style.
// If forceStyle is true, newStr's indentation is force-converted to fileStyle even on direct match.
func Replace(content, oldStr, newStr string, replaceAll bool, fileStyle IndentStyle, forceStyle bool) ReplaceResult {
	// Search runs on an LF-normalized view of the file, never on raw bytes.
	// old_string arrives from JSON with LF newlines, while a file can hold CRLF
	// in one region and LF in another (a CRLF-era file with later LF-only
	// edits). Converting the needle to the file's *dominant* newline made every
	// minority-newline region permanently unmatchable for multi-line anchors.
	// Matching the normalized view and mapping the hit back to an exact byte
	// span keeps untouched newlines byte-identical.
	m := common.NewLineEndingMap(content)
	norm := m.Norm
	normalizedOld := common.NormalizeLineEndings(oldStr, "\n")
	normalizedNew := common.NormalizeLineEndings(newStr, "\n")

	// 1st pass: direct match with original string.
	// When old_string has leading whitespace, require line-boundary alignment
	// (match must start at position 0 or immediately after '\n').
	// This prevents a shallowly-indented old_string from matching as a
	// substring inside a more-deeply-indented line, which would produce
	// incorrect indentation in the replacement -- especially for multiline
	// new_string where only the first line would inherit the surrounding tabs.
	var count int
	if hasLeadingWhitespace(normalizedOld) {
		count = lineStartCount(norm, normalizedOld)
	} else {
		count = strings.Count(norm, normalizedOld)
	}
	if count > 0 {
		finalNew := normalizedNew
		// forceStyle: force-convert newStr to fileStyle when indent_style is explicitly specified
		if forceStyle {
			newStyle := DetectIndentOfString(newStr)
			if newStyle.UseTabs != fileStyle.UseTabs || newStyle.IndentSize != fileStyle.IndentSize {
				finalNew = ConvertIndent(normalizedNew, newStyle, fileStyle)
			}
		}
		if hasLeadingWhitespace(normalizedOld) {
			return applyLineStartReplace(m, normalizedOld, finalNew, replaceAll)
		}
		return applyReplace(m, normalizedOld, finalNew, replaceAll)
	}

	// 2nd pass: match after indent conversion (spaces -> tabs or tabs -> spaces)
	srcStyle := DetectIndentOfString(oldStr)
	if srcStyle.UseTabs != fileStyle.UseTabs {
		convertedOld := ConvertIndent(normalizedOld, srcStyle, fileStyle)
		convertedNew := ConvertIndent(normalizedNew, srcStyle, fileStyle)

		if strings.Count(norm, convertedOld) > 0 {
			return applyReplace(m, convertedOld, convertedNew, replaceAll)
		}
	}

	// 3rd pass: force conversion when file uses tabs but old_string has spaces
	if fileStyle.UseTabs && HasLeadingSpaces(normalizedOld) {
		convertedOld := SpacesToTabs(normalizedOld, fileStyle.IndentSize)
		convertedNew := SpacesToTabs(normalizedNew, fileStyle.IndentSize)

		if strings.Count(norm, convertedOld) > 0 {
			return applyReplace(m, convertedOld, convertedNew, replaceAll)
		}
	}

	// 4th pass: brute-force indent sizes (2, 3, 4, 8) when auto-detection fails.
	// LLMs often use a different indent size than the file's actual tab stops,
	// causing deep nesting (6-7 levels) to mismatch after conversion.
	if fileStyle.UseTabs && HasLeadingSpaces(normalizedOld) {
		for _, trySize := range []int{2, 3, 4, 5, 6, 7, 8} {
			convertedOld := SpacesToTabs(normalizedOld, trySize)
			if convertedOld == normalizedOld {
				continue // no change, skip
			}
			if strings.Count(norm, convertedOld) > 0 {
				convertedNew := SpacesToTabs(normalizedNew, trySize)
				return applyReplace(m, convertedOld, convertedNew, replaceAll)
			}
		}
	}

	// 5th pass: reverse -- file uses spaces but old_string has tabs
	if !fileStyle.UseTabs && hasLeadingTabs(normalizedOld) {
		for _, trySize := range []int{2, 3, 4, 5, 6, 7, 8} {
			convertedOld := TabsToSpaces(normalizedOld, trySize)
			if strings.Count(norm, convertedOld) > 0 {
				convertedNew := TabsToSpaces(normalizedNew, trySize)
				return applyReplace(m, convertedOld, convertedNew, replaceAll)
			}
		}
	}

	// 6th pass: tab depth normalization.
	// Handles the case where both file and old_string use tabs but have different
	// base indentation depth (e.g. old_string has 2 tabs, file has 3 tabs).
	// Passes 2-4 only handle tabs<->spaces conversion, not depth differences.
	// Tries shifting old_string by 0-10 tabs, preserving relative indentation.
	if fileStyle.UseTabs && hasLeadingTabs(normalizedOld) {
		// minTabsNew is computed independently from minTabsOld so that tabDelta
		// captures the relative indent change between old and new. For example,
		// if old has min 2 tabs and new has min 3 tabs, new is always 1 level
		// deeper -- this relationship must be preserved when shifting to actual depth.
		//
		// Candidates are collected across all depths before picking the best one,
		// preferring unambiguous matches (count==1) over multiple matches, and
		// among equal ambiguity preferring depth closest to original minTabsOld.
		// This avoids incorrectly matching outer-scope code when the same snippet
		// appears at multiple indentation levels.
		minTabsOld := findMinLeadingTabs(normalizedOld)
		minTabsNew := findMinLeadingTabs(normalizedNew)
		tabDelta := minTabsNew - minTabsOld
		strippedOld := shiftTabs(normalizedOld, -minTabsOld)
		strippedNew := shiftTabs(normalizedNew, -minTabsNew)

		type candidate struct{ baseTabs, count int }
		var candidates []candidate
		for baseTabs := 0; baseTabs <= 10; baseTabs++ {
			if baseTabs == minTabsOld {
				continue // already tried this exact depth in pass 1
			}
			shiftedOld := shiftTabs(strippedOld, baseTabs)
			cnt := strings.Count(norm, shiftedOld)
			if cnt > 0 {
				candidates = append(candidates, candidate{baseTabs, cnt})
			}
		}
		if len(candidates) > 0 {
			absDist := func(a, b int) int {
				if a > b {
					return a - b
				}
				return b - a
			}
			best := candidates[0]
			for _, c := range candidates[1:] {
				cUniq := c.count == 1
				bUniq := best.count == 1
				if cUniq && !bUniq {
					best = c
				} else if cUniq == bUniq {
					// Same uniqueness: prefer depth closest to original.
					if absDist(c.baseTabs, minTabsOld) < absDist(best.baseTabs, minTabsOld) {
						best = c
					}
				}
			}
			shiftedOld := shiftTabs(strippedOld, best.baseTabs)
			// Clamp newDepth to 0: when new_string is shallower than old_string
			// (negative tabDelta), the computed depth can go below zero if the
			// actual file depth is smaller than |tabDelta|. Top-level (0 tabs)
			// is the minimum valid indentation.
			newDepth := best.baseTabs + tabDelta
			if newDepth < 0 {
				newDepth = 0
			}
			shiftedNew := shiftTabs(strippedNew, newDepth)
			return applyReplace(m, shiftedOld, shiftedNew, replaceAll)
		}
	}

	// 7th pass (diagnostic only): normalize all leading whitespace line-by-line
	// and check whether the content exists with different indentation.
	// Covers remaining cases (e.g. spaces in old_string, tabs in file) not caught
	// by passes 2-6. Does NOT auto-fix -- gives an actionable error message instead.
	normContent := normalizeIndent(norm)
	normOld := normalizeIndent(normalizedOld)
	if normOld != "" && strings.Contains(normContent, normOld) {
		return ReplaceResult{
			Applied: false,
			Message: "old_string not found: content exists in file but indentation differs (wrong number of tabs/spaces). Re-read the file to copy exact indentation.",
		}
	}

	return ReplaceResult{
		Applied: false,
		Message: "old_string not found in file",
	}
}

// findMinLeadingTabs returns the minimum number of leading tabs across all
// non-empty, non-whitespace-only lines. Empty lines are ignored so that
// blank lines inside a block do not incorrectly reduce the minimum to 0.
func findMinLeadingTabs(s string) int {
	min := -1
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		n := len(line) - len(strings.TrimLeft(line, "\t"))
		if min < 0 || n < min {
			min = n
		}
	}
	if min < 0 {
		return 0
	}
	return min
}

// shiftTabs adds (positive delta) or removes (negative delta) leading tabs
// from every line. Lines with fewer tabs than the removal amount get all
// their leading tabs stripped rather than going negative.
func shiftTabs(s string, delta int) string {
	if delta == 0 {
		return s
	}
	lines := strings.Split(s, "\n")
	prefix := ""
	if delta > 0 {
		prefix = strings.Repeat("\t", delta)
	}
	for i, line := range lines {
		if delta > 0 {
			lines[i] = prefix + line
		} else {
			toRemove := -delta
			tabCount := len(line) - len(strings.TrimLeft(line, "\t"))
			if tabCount < toRemove {
				toRemove = tabCount
			}
			lines[i] = line[toRemove:]
		}
	}
	return strings.Join(lines, "\n")
}

// normalizeIndent strips all leading whitespace from every line, preserving content.
// Used as a last-resort diagnostic to detect indentation mismatches.
func normalizeIndent(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimLeft(line, " \t")
	}
	return strings.Join(lines, "\n")
}

// applyReplace performs the actual replacement.
// If the match count is > 1 and replaceAll is false, returns an error without replacing.
func applyReplace(m *common.LineEndingMap, oldStr, newStr string, replaceAll bool) ReplaceResult {
	return applySpans(m, oldStr, newStr, false, replaceAll)
}

// applySpans rewrites the hits of oldStr found in the normalized view into the
// original bytes. Hits are streamed rather than collected first: one offset per
// hit is hundreds of MB when a short old_string matches a large file, and the
// ambiguity check below would never get the chance to reject that edit.
//
// Offsets are translated back to original byte offsets, so every byte outside a
// replaced span survives unchanged. newStr takes the newline form of the region
// it lands in rather than the file's dominant one -- otherwise an edit inside a
// minority-newline region would silently convert it.
func applySpans(m *common.LineEndingMap, oldStr, newStr string, lineStart, replaceAll bool) ReplaceResult {
	count := countOccurrences(m.Norm, oldStr, lineStart)
	if count == 0 {
		return ReplaceResult{Applied: false, Message: "old_string not found in file"}
	}
	if !replaceAll && count > 1 {
		return ReplaceResult{
			Applied: false,
			Message: fmt.Sprintf("old_string found %d times. Use replace_all=true or provide more context to make it unique", count),
		}
	}

	// Newline-free replacement text has nothing to convert, which also skips
	// the region lookup entirely -- the common single-line edit.
	fixedNew := !strings.ContainsAny(newStr, "\r\n")

	var sb strings.Builder
	sb.Grow(len(m.Original))
	prev := 0
	for i := 0; i+len(oldStr) <= len(m.Norm); {
		idx := strings.Index(m.Norm[i:], oldStr)
		if idx < 0 {
			break
		}
		pos := i + idx
		i = pos + len(oldStr)
		if lineStart && pos != 0 && m.Norm[pos-1] != '\n' {
			continue
		}
		sb.WriteString(m.Original[prev:m.OrigOffset(pos)])
		if fixedNew {
			sb.WriteString(newStr)
		} else {
			sb.WriteString(common.NormalizeLineEndings(newStr, m.LocalLineEnding(pos, pos+len(oldStr))))
		}
		prev = m.OrigOffset(pos + len(oldStr))
		if !replaceAll {
			break
		}
	}
	sb.WriteString(m.Original[prev:])

	return ReplaceResult{
		Content:    sb.String(),
		MatchCount: count,
		Applied:    true,
		Message:    fmt.Sprintf("replaced %d occurrence(s)", count),
	}
}

// hasLeadingWhitespace returns true if the first character of s is a tab or space.
// Used to decide whether line-boundary anchoring is needed in pass 1.
func hasLeadingWhitespace(s string) bool {
	return len(s) > 0 && (s[0] == '\t' || s[0] == ' ')
}

// countOccurrences counts hits of sub in s left to right without overlap, the
// same counting strings.Count does. When lineStart is set, only hits beginning
// at a line boundary (offset 0 or right after '\n') are counted -- but a
// rejected hit still advances the cursor past itself, so the count matches what
// applySpans replaces.
func countOccurrences(s, sub string, lineStart bool) int {
	if sub == "" {
		return 0
	}
	if !lineStart {
		return strings.Count(s, sub)
	}
	n := 0
	for i := 0; i+len(sub) <= len(s); {
		idx := strings.Index(s[i:], sub)
		if idx < 0 {
			break
		}
		pos := i + idx
		i = pos + len(sub)
		if pos == 0 || s[pos-1] == '\n' {
			n++
		}
	}
	return n
}

// lineStartCount counts occurrences of sub in s that start at a line boundary.
func lineStartCount(s, sub string) int {
	return countOccurrences(s, sub, true)
}

// applyLineStartReplace is like applyReplace but only replaces occurrences
// of oldStr that start at a line boundary.
func applyLineStartReplace(m *common.LineEndingMap, oldStr, newStr string, replaceAll bool) ReplaceResult {
	return applySpans(m, oldStr, newStr, true, replaceAll)
}

// hasLeadingTabs returns true if any line in text starts with a tab.
func hasLeadingTabs(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if len(line) > 0 && line[0] == '\t' {
			return true
		}
	}
	return false
}
