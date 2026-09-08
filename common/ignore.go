package common

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

var defaultIgnoredDirs = map[string]bool{
	".git": true, ".svn": true, ".hg": true,
	"node_modules": true, "vendor": true, "target": true,
	"build": true, "dist": true, "coverage": true,
	"__pycache__": true, ".venv": true, "venv": true,
}

// IsDefaultIgnoredDir reports whether name is a common VCS, generated, or
// dependency directory that search tools skip unless include_ignored is set.
func IsDefaultIgnoredDir(name string) bool {
	return defaultIgnoredDirs[strings.ToLower(name)]
}

type ignorePattern struct {
	pattern  string
	negate   bool
	dirOnly  bool
	anchored bool
}

// RootIgnoreRules contains patterns from a search root's .gitignore and
// .ignore files. Patterns from .ignore are appended last so they can override
// matching .gitignore rules, mirroring the purpose of a search-specific ignore
// file.
type RootIgnoreRules struct {
	patterns []ignorePattern
}

// LoadRootIgnoreRules reads the search root's .gitignore and .ignore files.
// Root-only loading keeps startup proportional to the actual traversal; nested
// ignore files can be supported separately without changing this contract.
func LoadRootIgnoreRules(root string) *RootIgnoreRules {
	var patterns []ignorePattern
	for _, name := range []string{".gitignore", ".ignore"} {
		patterns = append(patterns, loadIgnoreFile(filepath.Join(root, name))...)
	}
	if len(patterns) == 0 {
		return nil
	}
	return &RootIgnoreRules{patterns: patterns}
}

func loadIgnoreFile(path string) []ignorePattern {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var patterns []ignorePattern
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := ignorePattern{}
		if strings.HasPrefix(line, "!") {
			p.negate = true
			line = strings.TrimPrefix(line, "!")
		}
		if strings.HasSuffix(line, "/") {
			p.dirOnly = true
			line = strings.TrimSuffix(line, "/")
		}
		p.anchored = strings.HasPrefix(line, "/") || strings.Contains(strings.TrimPrefix(line, "/"), "/")
		line = strings.TrimPrefix(line, "/")
		p.pattern = filepath.ToSlash(line)
		if p.pattern != "" {
			patterns = append(patterns, p)
		}
	}
	return patterns
}

// Match reports whether a path relative to the search root is ignored.
func (rules *RootIgnoreRules) Match(rel string, isDir bool) bool {
	if rules == nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	matched := false
	for _, pattern := range rules.patterns {
		if pattern.dirOnly && !isDir {
			continue
		}
		if matchIgnoreGlob(pattern, rel) {
			matched = !pattern.negate
		}
	}
	return matched
}

// MatchPath also checks parent directories. It is useful when paths came from
// filepath.Glob rather than a walk that could prune ignored directories.
func (rules *RootIgnoreRules) MatchPath(rel string, isDir bool) bool {
	if rules == nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		if rules.Match(strings.Join(parts[:i], "/"), true) {
			return true
		}
	}
	return rules.Match(rel, isDir)
}

func matchIgnoreGlob(pattern ignorePattern, rel string) bool {
	if pattern.anchored {
		return ignoreGlobMatch(pattern.pattern, rel)
	}
	parts := strings.Split(rel, "/")
	for i := range parts {
		if ignoreGlobMatch(pattern.pattern, strings.Join(parts[i:], "/")) {
			return true
		}
	}
	return false
}

// ignoreGlobMatch supports the common ignore-file ** forms while delegating
// ordinary wildcard semantics to filepath.Match.
func ignoreGlobMatch(pattern, name string) bool {
	pattern = filepath.FromSlash(pattern)
	name = filepath.FromSlash(name)
	if !strings.Contains(pattern, "**") {
		matched, _ := filepath.Match(pattern, name)
		return matched
	}
	if strings.HasPrefix(pattern, "**"+string(filepath.Separator)) {
		rest := strings.TrimPrefix(pattern, "**"+string(filepath.Separator))
		parts := strings.Split(filepath.ToSlash(name), "/")
		for i := range parts {
			candidate := filepath.FromSlash(strings.Join(parts[i:], "/"))
			if matched, _ := filepath.Match(rest, candidate); matched {
				return true
			}
		}
	}
	if strings.HasSuffix(pattern, string(filepath.Separator)+"**") {
		prefix := strings.TrimSuffix(pattern, string(filepath.Separator)+"**")
		return name == prefix || strings.HasPrefix(name, prefix+string(filepath.Separator))
	}
	segments := strings.Split(pattern, "**")
	if len(segments) == 2 {
		return strings.HasPrefix(name, strings.TrimSuffix(segments[0], string(filepath.Separator))) &&
			strings.HasSuffix(name, strings.TrimPrefix(segments[1], string(filepath.Separator)))
	}
	return false
}
