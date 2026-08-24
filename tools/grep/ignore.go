package grep

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

func isDefaultIgnoredDir(name string) bool {
	return defaultIgnoredDirs[strings.ToLower(name)]
}

type ignorePattern struct {
	pattern  string
	negate   bool
	dirOnly  bool
	anchored bool
}

type rootIgnoreRules struct {
	patterns []ignorePattern
}

// loadRootGitignore deliberately reads only the search root's .gitignore.
// This covers the dominant generated/vendor exclusions without pre-walking the
// whole tree before grep itself starts. Nested ignore files can be added later
// without changing the public include_ignored contract.
func loadRootGitignore(root string) *rootIgnoreRules {
	f, err := os.Open(filepath.Join(root, ".gitignore"))
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
		line = strings.TrimPrefix(line, "/")
		p.anchored = strings.Contains(line, "/")
		p.pattern = filepath.ToSlash(line)
		if p.pattern != "" {
			patterns = append(patterns, p)
		}
	}
	if len(patterns) == 0 {
		return nil
	}
	return &rootIgnoreRules{patterns: patterns}
}

func (rules *rootIgnoreRules) match(rel string, isDir bool) bool {
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

func matchIgnoreGlob(pattern ignorePattern, rel string) bool {
	if pattern.anchored {
		return globMatch(pattern.pattern, rel)
	}
	parts := strings.Split(rel, "/")
	for i := range parts {
		if globMatch(pattern.pattern, strings.Join(parts[i:], "/")) {
			return true
		}
	}
	return false
}

// globMatch supports the common gitignore ** forms while delegating ordinary
// wildcard semantics to filepath.Match.
func globMatch(pattern, name string) bool {
	pattern = filepath.FromSlash(pattern)
	name = filepath.FromSlash(name)
	if !strings.Contains(pattern, "**") {
		matched, _ := filepath.Match(pattern, name)
		if matched {
			return true
		}
		matched, _ = filepath.Match(pattern, filepath.Base(name))
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
