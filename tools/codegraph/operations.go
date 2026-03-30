package codegraph

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"agent-tool/common"
)

// opIndex walks a directory, parses all supported files, and stores results in SQLite.
func opIndex(input CodeGraphInput) (string, error) {
	if input.Path == "" {
		return "", fmt.Errorf("path is required for index operation")
	}
	root := filepath.Clean(input.Path)
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("path must be absolute")
	}
	if err := common.CheckDangerousPath(root); err != nil {
		return "", err
	}
	if !common.GetAllowSymlinks() {
		if lfi, err := os.Lstat(root); err == nil && lfi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlinks are not allowed (see set_config allow_symlinks)")
		}
	}
	fi, err := os.Stat(root)
	if err != nil {
		return "", fmt.Errorf("cannot access path: %w", err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("path must be a directory")
	}

	db, err := openDB(root)
	if err != nil {
		return "", fmt.Errorf("db: %w", err)
	}
	defer db.Close()

	var indexed, skipped int
	var indexedAtomic, skippedAtomic, errorsAtomic int64
	t0 := time.Now()

	// Load .gitignore patterns for filtering
	gitIgnore := loadGitignore(root)

	// Phase 1: collect files to index
	type fileEntry struct {
		path string
		lang string
	}
	var files []fileEntry

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !common.GetAllowSymlinks() {
			if lfi, lerr := os.Lstat(path); lerr == nil && lfi.Mode()&os.ModeSymlink != 0 {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if isSkippedDir(base) {
				return filepath.SkipDir
			}
			// Check .gitignore patterns
			if gitIgnore != nil {
				rel, err := filepath.Rel(root, path)
				if err == nil && gitIgnore.match(rel, true) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if info.Size() > 10*1024*1024 {
			return nil
		}
		lang := detectLanguage(path, input.Language)
		if lang == "" {
			return nil
		}
		// Check .gitignore patterns for files
		if gitIgnore != nil {
			rel, err := filepath.Rel(root, path)
			if err == nil && gitIgnore.match(rel, false) {
				return nil
			}
		}
		changed, _ := isFileChanged(db, path)
		if !changed {
			atomic.AddInt64(&skippedAtomic, 1)
			return nil
		}
		files = append(files, fileEntry{path, lang})
		return nil
	})

	// Phase 2: parallel parse + sequential DB store
	type parseJob struct {
		path   string
		lang   string
		result *ParseResult
	}

	resultsCh := make(chan parseJob, 64)
	var wg sync.WaitGroup

	// Worker goroutines for parsing
	numWorkers := poolSize
	if input.Workers > 0 {
		numWorkers = input.Workers
		if numWorkers > 32 {
			numWorkers = 32 // cap to prevent excessive memory usage
		}
	}
	if len(files) < numWorkers {
		numWorkers = len(files)
	}
	if numWorkers < 1 {
		numWorkers = 1
	}
	fileCh := make(chan fileEntry, len(files))
	for _, f := range files {
		fileCh <- f
	}
	close(fileCh)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range fileCh {
				data, err := os.ReadFile(f.path)
				if err != nil {
					atomic.AddInt64(&errorsAtomic, 1)
					continue
				}
				eng, err := getEngine(f.lang)
				if err != nil {
					atomic.AddInt64(&errorsAtomic, 1)
					continue
				}
				result, err := eng.Parse(string(data))
				putEngine(eng)
				if err != nil {
					atomic.AddInt64(&errorsAtomic, 1)
					continue
				}
				resultsCh <- parseJob{f.path, f.lang, result}
			}
		}()
	}

	// Close results channel when all workers done
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Sequential DB store with batch transactions
	// SQLite is much faster when multiple inserts are in one transaction
	batchSize := 100
	batch := make([]parseJob, 0, batchSize)

	flushBatch := func() {
		if len(batch) == 0 {
			return
		}
		tx, err := db.Begin()
		if err != nil {
			atomic.AddInt64(&errorsAtomic, int64(len(batch)))
			batch = batch[:0]
			return
		}
		defer tx.Rollback() // no-op after successful Commit
		var committed int64
		for _, job := range batch {
			if err := storeParseResultTx(tx, job.path, job.lang, job.result); err != nil {
				atomic.AddInt64(&errorsAtomic, 1)
				continue
			}
			committed++
		}
		if err := tx.Commit(); err != nil {
			// Commit failed = all rolled back, count all as errors
			atomic.AddInt64(&errorsAtomic, committed)
		} else {
			atomic.AddInt64(&indexedAtomic, committed)
		}
		batch = batch[:0]
	}

	for job := range resultsCh {
		batch = append(batch, job)
		if len(batch) >= batchSize {
			flushBatch()
		}
	}
	flushBatch() // flush remaining

	indexed = int(indexedAtomic)
	skipped = int(skippedAtomic)
	errors := int(errorsAtomic)

	elapsed := time.Since(t0)
	return fmt.Sprintf("Index complete: %d files indexed, %d unchanged (skipped), %d errors\nTime: %s\nDB: %s",
		indexed, skipped, errors, elapsed.Round(time.Millisecond), filepath.Join(root, dbFileName)), nil
}

// opFind searches for symbol definitions by name.
// Supports fuzzy matching: if name contains '*' it is treated as a glob pattern
// (e.g. "Get*" matches GetPlayer, GetName). Otherwise exact match + qualified_name suffix.
func opFind(input CodeGraphInput) (string, error) {
	if input.Name == "" {
		return "", fmt.Errorf("name is required for find operation")
	}

	db, err := validateAndOpenDB(input.Path)
	if err != nil {
		return "", err
	}
	defer db.Close()

	var rows *sql.Rows
	if strings.Contains(input.Name, "*") {
		// Fuzzy mode: convert glob '*' to SQL LIKE '%'
		likePattern := strings.ReplaceAll(escapeLike(strings.ReplaceAll(input.Name, "*", "\x00")), "\x00", "%")
		rows, err = db.Query(`
			SELECT s.name, s.qualified_name, s.kind, f.path, s.line, s.scope
			FROM symbols s JOIN files f ON s.file_id = f.id
			WHERE s.name LIKE ? ESCAPE '\' OR s.qualified_name LIKE ? ESCAPE '\'
			ORDER BY s.kind, f.path, s.line
			LIMIT 50
		`, likePattern, likePattern)
	} else {
		// Exact mode (existing behavior)
		escaped := escapeLike(input.Name)
		rows, err = db.Query(`
			SELECT s.name, s.qualified_name, s.kind, f.path, s.line, s.scope
			FROM symbols s JOIN files f ON s.file_id = f.id
			WHERE s.name = ? OR s.qualified_name = ? OR s.qualified_name LIKE ? ESCAPE '\'
			ORDER BY s.kind, f.path, s.line
			LIMIT 50
		`, input.Name, input.Name, "%::"+escaped)
	}
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var sb strings.Builder
	count := 0
	for rows.Next() {
		var name, qn, kind, path, scope string
		var line int
		if err := rows.Scan(&name, &qn, &kind, &path, &line, &scope); err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("[%s] %s  %s:%d", kind, qn, path, line))
		if scope != "" {
			sb.WriteString(fmt.Sprintf("  (scope: %s)", scope))
		}
		sb.WriteString("\n")
		count++
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("query error: %w", err)
	}

	if count == 0 {
		return fmt.Sprintf("No symbols found matching %q. Run codegraph(op=\"index\", path=\"...\") first.", input.Name), nil
	}
	return fmt.Sprintf("Found %d result(s):\n%s", count, sb.String()), nil
}

// opCallers finds all call sites that invoke a function/method.
func opCallers(input CodeGraphInput) (string, error) {
	if input.Name == "" {
		return "", fmt.Errorf("name is required for callers operation")
	}

	db, err := validateAndOpenDB(input.Path)
	if err != nil {
		return "", err
	}
	defer db.Close()

	// Exact match only for callers - LIKE '%name%' causes false positives
	// (e.g. "SetDead" matching "WIN_ResetDeadKeys")
	rows, err := db.Query(`
		SELECT c.callee_name, f.path, c.caller_line, c.scope
		FROM calls c JOIN files f ON c.caller_file_id = f.id
		WHERE c.callee_name = ?
		ORDER BY f.path, c.caller_line
		LIMIT 100
	`, input.Name)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var sb strings.Builder
	count := 0
	for rows.Next() {
		var callee, path, scope string
		var line int
		if err := rows.Scan(&callee, &path, &line, &scope); err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %s:%d  calls %s", path, line, callee))
		if scope != "" {
			sb.WriteString(fmt.Sprintf("  (in: %s)", scope))
		}
		sb.WriteString("\n")
		count++
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("query error: %w", err)
	}

	if count == 0 {
		return fmt.Sprintf("No callers found for %q.", input.Name), nil
	}
	return fmt.Sprintf("Callers of %q (%d):\n%s", input.Name, count, sb.String()), nil
}

// opCallees finds all functions/methods called by a function.
func opCallees(input CodeGraphInput) (string, error) {
	if input.Name == "" {
		return "", fmt.Errorf("name is required for callees operation")
	}

	db, err := validateAndOpenDB(input.Path)
	if err != nil {
		return "", err
	}
	defer db.Close()

	// Find the function's line range, then find calls within that range
	var fileID int
	var startLine, endLine int

	escaped := escapeLike(input.Name)
	err = db.QueryRow(`
		SELECT s.file_id, s.line, COALESCE(
			(SELECT MIN(s2.line) - 1 FROM symbols s2 WHERE s2.file_id = s.file_id AND s2.line > s.line AND s2.kind IN ('function','method')),
			s.line + 1000
		)
		FROM symbols s
		WHERE (s.name = ? OR s.qualified_name = ? OR s.qualified_name LIKE ? ESCAPE '\') AND s.kind IN ('function','method')
		LIMIT 1
	`, input.Name, input.Name, "%::"+escaped).Scan(&fileID, &startLine, &endLine)
	if err != nil {
		return fmt.Sprintf("Symbol %q not found in index.", input.Name), nil
	}

	rows, err := db.Query(`
		SELECT c.callee_name, c.caller_line
		FROM calls c
		WHERE c.caller_file_id = ? AND c.caller_line >= ? AND c.caller_line <= ?
		ORDER BY c.caller_line
	`, fileID, startLine, endLine)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var sb strings.Builder
	count := 0
	for rows.Next() {
		var callee string
		var line int
		if err := rows.Scan(&callee, &line); err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("  line:%d  %s\n", line, callee))
		count++
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("query error: %w", err)
	}

	if count == 0 {
		return fmt.Sprintf("No callees found for %q.", input.Name), nil
	}
	return fmt.Sprintf("Callees of %q (%d):\n%s", input.Name, count, sb.String()), nil
}

// opSymbols lists all symbols in a file by parsing it with tree-sitter.
func opSymbols(input CodeGraphInput) (string, error) {
	if input.Path == "" {
		return "", fmt.Errorf("path is required for symbols operation")
	}
	path := filepath.Clean(input.Path)
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute")
	}

	lang := detectLanguage(path, input.Language)
	if lang == "" {
		return "", fmt.Errorf("unsupported file type: %s", filepath.Ext(path))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot read file: %w", err)
	}
	if len(data) > 10*1024*1024 {
		return "", fmt.Errorf("file too large (%d bytes, max 10MB)", len(data))
	}

	eng, err := getEngine(lang)
	if err != nil {
		return "", fmt.Errorf("engine init: %w", err)
	}

	result, err := eng.Parse(string(data))
	putEngine(eng)
	if err != nil {
		return "", fmt.Errorf("parse failed: %w", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("File: %s\n\n", path))

	if len(result.Classes) > 0 {
		sb.WriteString("Classes:\n")
		for _, s := range result.Classes {
			scope := ""
			if s.Scope != "" {
				scope = fmt.Sprintf(" (scope: %s)", s.Scope)
			}
			sb.WriteString(fmt.Sprintf("  %s %s  line:%d%s\n", s.NodeType, s.Name, s.Line, scope))
		}
		sb.WriteString("\n")
	}

	if len(result.Functions) > 0 {
		sb.WriteString("Functions/Methods:\n")
		for _, s := range result.Functions {
			scope := ""
			if s.Scope != "" {
				scope = fmt.Sprintf(" (scope: %s)", s.Scope)
			}
			parent := ""
			if s.Parent == "field_declaration_list" {
				parent = " [inline]"
			}
			sb.WriteString(fmt.Sprintf("  %s  line:%d%s%s\n", cleanSymbolName(s.Name), s.Line, scope, parent))
		}
		sb.WriteString("\n")
	}

	if len(result.Imports) > 0 {
		sb.WriteString("Imports/Includes:\n")
		for _, s := range result.Imports {
			sb.WriteString(fmt.Sprintf("  %s  line:%d\n", s.Name, s.Line))
		}
		sb.WriteString("\n")
	}

	if len(result.Inheritance) > 0 {
		sb.WriteString("Inheritance:\n")
		for _, inh := range result.Inheritance {
			sb.WriteString(fmt.Sprintf("  %s -> %s  line:%d\n", inh.ClassName, inh.ParentName, inh.Line))
		}
		sb.WriteString("\n")
	}

	if len(result.Calls) > 0 {
		callCount := 0
		for _, s := range result.Calls {
			if s.Capture == "call" {
				callCount++
			}
		}
		sb.WriteString(fmt.Sprintf("Calls: %d\n", callCount))
		for _, s := range result.Calls {
			if s.Capture == "callee" {
				scope := ""
				if s.Scope != "" {
					scope = fmt.Sprintf(" (in: %s)", s.Scope)
				}
				sb.WriteString(fmt.Sprintf("  line:%d%s\n", s.Line, scope))
			}
		}
	}

	return sb.String(), nil
}

// opMethods lists all methods of a class.
func opMethods(input CodeGraphInput) (string, error) {
	if input.Name == "" {
		return "", fmt.Errorf("name is required for methods operation")
	}

	db, err := validateAndOpenDB(input.Path)
	if err != nil {
		return "", err
	}
	defer db.Close()

	escaped := escapeLike(input.Name)
	rows, err := db.Query(`
		SELECT s.name, s.qualified_name, f.path, s.line
		FROM symbols s JOIN files f ON s.file_id = f.id
		WHERE s.kind = 'method' AND (s.scope = ? OR s.qualified_name LIKE ? ESCAPE '\')
		ORDER BY f.path, s.line
		LIMIT 100
	`, input.Name, escaped+"::%")
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var sb strings.Builder
	count := 0
	for rows.Next() {
		var name, qn, path string
		var line int
		if err := rows.Scan(&name, &qn, &path, &line); err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %s  %s:%d\n", qn, path, line))
		count++
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("query error: %w", err)
	}

	if count == 0 {
		return fmt.Sprintf("No methods found for class %q.", input.Name), nil
	}
	return fmt.Sprintf("Methods of %q (%d):\n%s", input.Name, count, sb.String()), nil
}

// opInherits shows inheritance hierarchy.
func opInherits(input CodeGraphInput) (string, error) {
	if input.Name == "" {
		return "", fmt.Errorf("name is required for inherits operation")
	}

	db, err := validateAndOpenDB(input.Path)
	if err != nil {
		return "", err
	}
	defer db.Close()

	var sb strings.Builder

	// Parents (what does this class extend/implement?)
	rows, err := db.Query(`
		SELECT i.parent_name, f.path, i.line
		FROM inheritance i JOIN files f ON i.file_id = f.id
		WHERE i.class_name = ?
		ORDER BY f.path, i.line
	`, input.Name)
	if err != nil {
		return "", err
	}

	sb.WriteString(fmt.Sprintf("Inheritance of %q:\n\n", input.Name))
	sb.WriteString("Parents (extends/implements):\n")
	parentCount := 0
	for rows.Next() {
		var parent, path string
		var line int
		if err := rows.Scan(&parent, &path, &line); err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %s  (%s:%d)\n", parent, path, line))
		parentCount++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", fmt.Errorf("query error: %w", err)
	}
	rows.Close()
	if parentCount == 0 {
		sb.WriteString("  (none)\n")
	}

	// Children (what classes extend this one?)
	rows2, err := db.Query(`
		SELECT i.class_name, f.path, i.line
		FROM inheritance i JOIN files f ON i.file_id = f.id
		WHERE i.parent_name = ?
		ORDER BY f.path, i.line
	`, input.Name)
	if err != nil {
		return "", err
	}

	sb.WriteString("\nChildren (extended by):\n")
	childCount := 0
	for rows2.Next() {
		var child, path string
		var line int
		if err := rows2.Scan(&child, &path, &line); err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %s  (%s:%d)\n", child, path, line))
		childCount++
	}
	if err := rows2.Err(); err != nil {
		rows2.Close()
		return "", fmt.Errorf("query error: %w", err)
	}
	rows2.Close()
	if childCount == 0 {
		sb.WriteString("  (none)\n")
	}

	if parentCount == 0 && childCount == 0 {
		return fmt.Sprintf("No inheritance info for %q. Run codegraph(op=\"index\") first.", input.Name), nil
	}

	return sb.String(), nil
}

// escapeLike escapes LIKE wildcard characters to prevent unintended pattern matching.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// validateAndOpenDB validates the path and opens the codegraph database.
func validateAndOpenDB(path string) (*sql.DB, error) {
	if path == "" {
		return nil, fmt.Errorf("path (project root) is required to locate the index database")
	}
	root := filepath.Clean(path)
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("path must be absolute")
	}
	if err := common.CheckDangerousPath(root); err != nil {
		return nil, err
	}
	if !common.GetAllowSymlinks() {
		if lfi, err := os.Lstat(root); err == nil && lfi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlinks are not allowed (see set_config allow_symlinks)")
		}
	}
	return openDB(root)
}

// isSkippedDir returns true for directories that should never be indexed.
// These are universally non-source directories across all ecosystems.
func isSkippedDir(base string) bool {
	switch base {
	case ".git", "node_modules", "__pycache__",
		".vs", ".vscode", ".idea",
		"build", "bin", "obj",
		"Debug", "Release", "x64",
		// Python virtual environments
		"venv", ".venv", "env",
		// Vendored / third-party dependencies
		"vendor", "third_party", "3rdparty", "external",
		// Build output
		"dist", "out", "target",
		// Other common non-source dirs
		".tox", ".mypy_cache", ".pytest_cache",
		"coverage", ".gradle", ".cargo":
		return true
	}
	return false
}

// gitignoreSet holds patterns from multiple .gitignore files (root + nested).
type gitignoreSet struct {
	layers []gitignoreLayer // ordered: root first, deeper dirs later
}

// gitignoreLayer holds patterns from one .gitignore file with its directory prefix.
type gitignoreLayer struct {
	prefix   string // relative dir (e.g. "" for root, "src/lib" for nested)
	patterns []gitignorePattern
}

type gitignorePattern struct {
	pattern  string
	negate   bool
	dirOnly  bool
	anchored bool // pattern contains '/' -> anchored to its .gitignore location
}

// loadGitignore reads .gitignore from root and all subdirectories.
// Returns nil if no .gitignore exists anywhere.
func loadGitignore(root string) *gitignoreSet {
	var layers []gitignoreLayer

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || isSkippedDir(base) {
				return filepath.SkipDir
			}
			// Skip symlink directories to prevent traversal outside project root
			if lfi, lerr := os.Lstat(path); lerr == nil && lfi.Mode()&os.ModeSymlink != 0 {
				return filepath.SkipDir
			}
			// Try to load .gitignore in this directory
			gi := filepath.Join(path, ".gitignore")
			patterns := parseGitignoreFile(gi)
			if len(patterns) > 0 {
				rel, _ := filepath.Rel(root, path)
				rel = filepath.ToSlash(rel)
				if rel == "." {
					rel = ""
				}
				layers = append(layers, gitignoreLayer{prefix: rel, patterns: patterns})
			}
		}
		return nil
	})

	if len(layers) == 0 {
		return nil
	}
	return &gitignoreSet{layers: layers}
}

// parseGitignoreFile reads and parses a single .gitignore file.
func parseGitignoreFile(path string) []gitignorePattern {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var patterns []gitignorePattern
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		p := gitignorePattern{}
		if line[0] == '!' {
			p.negate = true
			line = line[1:]
		}
		if strings.HasSuffix(line, "/") {
			p.dirOnly = true
			line = strings.TrimSuffix(line, "/")
		}
		// Contains '/' (excluding leading/trailing) -> anchored
		trimmed := strings.TrimPrefix(line, "/")
		p.anchored = strings.Contains(trimmed, "/")
		line = trimmed
		p.pattern = line
		if p.pattern != "" {
			patterns = append(patterns, p)
		}
	}
	return patterns
}

// match checks if a relative path matches any gitignore pattern across all layers.
func (g *gitignoreSet) match(rel string, isDir bool) bool {
	rel = filepath.ToSlash(rel)
	matched := false
	for _, layer := range g.layers {
		// Compute path relative to this .gitignore's directory
		var localRel string
		if layer.prefix == "" {
			localRel = rel
		} else {
			if !strings.HasPrefix(rel, layer.prefix+"/") && rel != layer.prefix {
				continue // path not under this .gitignore's directory
			}
			localRel = strings.TrimPrefix(rel, layer.prefix+"/")
		}
		for _, p := range layer.patterns {
			if p.dirOnly && !isDir {
				continue
			}
			if matchGlob(p, localRel) {
				matched = !p.negate
			}
		}
	}
	return matched
}

// matchGlob tests a single gitignore pattern against a relative path.
// Supports ** (match zero or more directories).
func matchGlob(p gitignorePattern, rel string) bool {
	pattern := p.pattern
	if p.anchored {
		// Anchored: match against full relative path
		return globMatch(pattern, rel)
	}
	// Unanchored: match against basename first
	base := rel
	if idx := strings.LastIndex(rel, "/"); idx >= 0 {
		base = rel[idx+1:]
	}
	if globMatch(pattern, base) {
		return true
	}
	// Also try matching against the full path (e.g. "*.o" should match "src/foo.o")
	if globMatch(pattern, rel) {
		return true
	}
	// Try matching at each directory level
	parts := strings.Split(rel, "/")
	for i := range parts {
		suffix := strings.Join(parts[i:], "/")
		if globMatch(pattern, suffix) {
			return true
		}
	}
	return false
}

// globMatch matches a pattern against a string, supporting ** for zero or more directories.
func globMatch(pattern, name string) bool {
	// Fast path: no ** in pattern, use filepath.Match
	if !strings.Contains(pattern, "**") {
		ok, _ := filepath.Match(pattern, name)
		return ok
	}

	// Split pattern by ** and match each segment
	segments := strings.Split(pattern, "**")

	// Handle leading **/ (match any prefix)
	if strings.HasPrefix(pattern, "**/") {
		rest := strings.TrimPrefix(pattern, "**/")
		// Match at any level
		if globMatch(rest, name) {
			return true
		}
		parts := strings.Split(name, "/")
		for i := 1; i < len(parts); i++ {
			if globMatch(rest, strings.Join(parts[i:], "/")) {
				return true
			}
		}
		return false
	}

	// Handle trailing /**
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		ok, _ := filepath.Match(prefix, name)
		if ok {
			return true
		}
		// Match anything under the prefix directory
		return strings.HasPrefix(name, prefix+"/") || name == prefix
	}

	// Handle middle /**/
	if len(segments) == 2 {
		prefix := strings.TrimSuffix(segments[0], "/")
		suffix := strings.TrimPrefix(segments[1], "/")
		// Direct match (zero directories between)
		combined := prefix + "/" + suffix
		if globMatch(combined, name) {
			return true
		}
		// Match with any number of directories between
		parts := strings.Split(name, "/")
		for i := 0; i < len(parts); i++ {
			left := strings.Join(parts[:i+1], "/")
			right := strings.Join(parts[i+1:], "/")
			leftOK, _ := filepath.Match(prefix, left)
			if prefix == "" {
				leftOK = true
				right = name
			}
			if leftOK && globMatch(suffix, right) {
				return true
			}
		}
		return false
	}

	// Fallback for complex multi-** patterns: try filepath.Match on each segment
	ok, _ := filepath.Match(pattern, name)
	return ok
}

// opStats returns summary statistics for the project index.
func opStats(input CodeGraphInput) (string, error) {
	db, err := validateAndOpenDB(input.Path)
	if err != nil {
		return "", err
	}
	defer db.Close()

	var files, classes, functions, methods, calls, includes, inheritance int
	db.QueryRow("SELECT COUNT(*) FROM files").Scan(&files)
	db.QueryRow("SELECT COUNT(*) FROM symbols WHERE kind='class'").Scan(&classes)
	db.QueryRow("SELECT COUNT(*) FROM symbols WHERE kind='function'").Scan(&functions)
	db.QueryRow("SELECT COUNT(*) FROM symbols WHERE kind='method'").Scan(&methods)
	db.QueryRow("SELECT COUNT(*) FROM calls").Scan(&calls)
	db.QueryRow("SELECT COUNT(*) FROM includes").Scan(&includes)
	db.QueryRow("SELECT COUNT(*) FROM inheritance").Scan(&inheritance)

	// Language breakdown
	langRows, err := db.Query("SELECT language, COUNT(*) FROM files GROUP BY language ORDER BY COUNT(*) DESC")
	if err != nil {
		return "", err
	}
	defer langRows.Close()

	var langBreakdown strings.Builder
	for langRows.Next() {
		var lang string
		var count int
		if err := langRows.Scan(&lang, &count); err != nil {
			continue
		}
		langBreakdown.WriteString(fmt.Sprintf("  %s: %d files\n", lang, count))
	}
	if err := langRows.Err(); err != nil {
		return "", fmt.Errorf("query error: %w", err)
	}

	return fmt.Sprintf("Project Index Stats:\n  Files: %d\n  Classes/Structs: %d\n  Functions: %d\n  Methods: %d\n  Call sites: %d\n  Imports/Includes: %d\n  Inheritance relations: %d\n\nLanguages:\n%s",
		files, classes, functions, methods, calls, includes, inheritance, langBreakdown.String()), nil
}

// opImporters finds files that import/include a given file.
func opImporters(input CodeGraphInput) (string, error) {
	if input.Name == "" {
		return "", fmt.Errorf("name is required (file name or include path to search for, e.g. \"dap_server.h\")")
	}

	db, err := validateAndOpenDB(input.Path)
	if err != nil {
		return "", err
	}
	defer db.Close()

	escaped := escapeLike(input.Name)
	rows, err := db.Query(`
		SELECT f.path, i.included, i.line
		FROM includes i JOIN files f ON i.file_id = f.id
		WHERE i.included LIKE ? ESCAPE '\'
		ORDER BY f.path, i.line
		LIMIT 100
	`, "%"+escaped+"%")
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var sb strings.Builder
	count := 0
	for rows.Next() {
		var path, included string
		var line int
		if err := rows.Scan(&path, &included, &line); err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %s:%d  imports %s\n", path, line, included))
		count++
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("query error: %w", err)
	}

	if count == 0 {
		return fmt.Sprintf("No files import/include %q.", input.Name), nil
	}
	return fmt.Sprintf("Files importing %q (%d):\n%s", input.Name, count, sb.String()), nil
}

// opUnused finds symbols (functions/methods) defined but never called.
func opUnused(input CodeGraphInput) (string, error) {
	db, err := validateAndOpenDB(input.Path)
	if err != nil {
		return "", err
	}
	defer db.Close()

	// Find functions/methods that have no matching call site.
	// Uses LEFT JOIN: symbols with no calls entry are "unused".
	rows, err := db.Query(`
		SELECT s.name, s.qualified_name, s.kind, f.path, s.line, s.scope
		FROM symbols s
		JOIN files f ON s.file_id = f.id
		LEFT JOIN calls c ON c.callee_name = s.name
		WHERE s.kind IN ('function', 'method') AND c.id IS NULL
		ORDER BY f.path, s.line
		LIMIT 200
	`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var sb strings.Builder
	count := 0
	for rows.Next() {
		var name, qn, kind, path, scope string
		var line int
		if err := rows.Scan(&name, &qn, &kind, &path, &line, &scope); err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("  [%s] %s  %s:%d", kind, qn, path, line))
		if scope != "" {
			sb.WriteString(fmt.Sprintf("  (scope: %s)", scope))
		}
		sb.WriteString("\n")
		count++
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("query error: %w", err)
	}

	if count == 0 {
		return "No unused functions/methods found. All defined symbols have callers.", nil
	}
	note := ""
	if count >= 200 {
		note = "\n(truncated at 200 results)"
	}
	return fmt.Sprintf("Unused symbols (%d):\n%s%s", count, sb.String(), note), nil
}

// opCallTree builds a recursive call hierarchy.
func opCallTree(input CodeGraphInput) (string, error) {
	if input.Name == "" {
		return "", fmt.Errorf("name is required for call_tree operation")
	}

	db, err := validateAndOpenDB(input.Path)
	if err != nil {
		return "", err
	}
	defer db.Close()

	maxDepth := input.Depth
	if maxDepth <= 0 {
		maxDepth = 3
	}
	if maxDepth > 10 {
		maxDepth = 10
	}

	direction := strings.ToLower(input.Direction)
	if direction == "" {
		direction = "up"
	}
	if direction != "up" && direction != "down" {
		return "", fmt.Errorf("direction must be 'up' (callers) or 'down' (callees), got %q", direction)
	}

	var sb strings.Builder
	if direction == "up" {
		sb.WriteString(fmt.Sprintf("Call tree (callers of %q, depth %d):\n", input.Name, maxDepth))
	} else {
		sb.WriteString(fmt.Sprintf("Call tree (callees of %q, depth %d):\n", input.Name, maxDepth))
	}

	visited := make(map[string]bool)
	nodeCount := 0
	buildCallTree(db, &sb, input.Name, direction, 0, maxDepth, visited, &nodeCount)

	return sb.String(), nil
}

// maxCallTreeNodes caps total output nodes to prevent exponential blowup.
const maxCallTreeNodes = 500

// buildCallTree recursively builds a call tree with indentation.
func buildCallTree(db *sql.DB, sb *strings.Builder, name, direction string, depth, maxDepth int, visited map[string]bool, nodeCount *int) {
	if depth >= maxDepth || *nodeCount >= maxCallTreeNodes {
		return
	}
	if visited[name] {
		indent := strings.Repeat("  ", depth+1)
		sb.WriteString(fmt.Sprintf("%s(circular: %s)\n", indent, name))
		return
	}
	visited[name] = true
	// Do NOT unset visited -- prevents exponential blowup in DAGs.

	var rows *sql.Rows
	var err error

	if direction == "up" {
		// Find callers of this function
		rows, err = db.Query(`
			SELECT DISTINCT c.scope, f.path, c.caller_line
			FROM calls c JOIN files f ON c.caller_file_id = f.id
			WHERE c.callee_name = ?
			ORDER BY f.path, c.caller_line
			LIMIT 50
		`, name)
	} else {
		// Find callees: first find this function's file and line range
		var fileID, startLine, endLine int
		escaped := escapeLike(name)
		err = db.QueryRow(`
			SELECT s.file_id, s.line, COALESCE(
				(SELECT MIN(s2.line) - 1 FROM symbols s2 WHERE s2.file_id = s.file_id AND s2.line > s.line AND s2.kind IN ('function','method')),
				s.line + 1000
			)
			FROM symbols s
			WHERE (s.name = ? OR s.qualified_name = ? OR s.qualified_name LIKE ? ESCAPE '\') AND s.kind IN ('function','method')
			LIMIT 1
		`, name, name, "%::"+escaped).Scan(&fileID, &startLine, &endLine)
		if err != nil {
			return
		}
		rows, err = db.Query(`
			SELECT DISTINCT c.callee_name, f.path, c.caller_line
			FROM calls c JOIN files f ON c.caller_file_id = f.id
			WHERE c.caller_file_id = ? AND c.caller_line >= ? AND c.caller_line <= ?
			ORDER BY c.caller_line
			LIMIT 50
		`, fileID, startLine, endLine)
	}
	if err != nil {
		return
	}
	defer rows.Close()

	indent := strings.Repeat("  ", depth+1)
	for rows.Next() {
		if *nodeCount >= maxCallTreeNodes {
			sb.WriteString(fmt.Sprintf("%s(truncated at %d nodes)\n", indent, maxCallTreeNodes))
			break
		}
		var ref, path string
		var line int
		if err := rows.Scan(&ref, &path, &line); err != nil {
			continue
		}
		*nodeCount++
		if direction == "up" {
			caller := ref
			if caller == "" {
				caller = "(global)"
			}
			sb.WriteString(fmt.Sprintf("%s%s  (%s:%d)\n", indent, caller, path, line))
			if caller != "(global)" && depth+1 < maxDepth {
				buildCallTree(db, sb, caller, direction, depth+1, maxDepth, visited, nodeCount)
			}
		} else {
			sb.WriteString(fmt.Sprintf("%s%s  (line:%d)\n", indent, ref, line))
			if depth+1 < maxDepth {
				buildCallTree(db, sb, ref, direction, depth+1, maxDepth, visited, nodeCount)
			}
		}
	}
}

// detectLanguage returns the language identifier from file extension or explicit hint.
func detectLanguage(path, hint string) string {
	if hint != "" {
		return strings.ToLower(hint)
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hxx", ".hh":
		return "cpp"
	case ".py":
		return "python"
	case ".go":
		return "go"
	case ".cs":
		return "csharp"
	// JS/TS: WASM not yet available, uncomment when added
	// case ".js", ".jsx":
	// 	return "javascript"
	// case ".ts", ".tsx":
	// 	return "typescript"
	case ".rs":
		return "rust"
	case ".java":
		return "java"
	}
	return ""
}
