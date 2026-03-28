package codegraph

import (
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
			if base == ".git" || base == "node_modules" || base == "__pycache__" ||
				base == ".vs" || base == ".vscode" || base == "build" || base == "bin" ||
				base == "obj" || base == "Debug" || base == "Release" || base == "x64" {
				return filepath.SkipDir
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
func opFind(input CodeGraphInput) (string, error) {
	if input.Name == "" {
		return "", fmt.Errorf("name is required for find operation")
	}

	db, err := validateAndOpenDB(input.Path)
	if err != nil {
		return "", err
	}
	defer db.Close()

	escaped := escapeLike(input.Name)
	rows, err := db.Query(`
		SELECT s.name, s.qualified_name, s.kind, f.path, s.line, s.scope
		FROM symbols s JOIN files f ON s.file_id = f.id
		WHERE s.name = ? OR s.qualified_name = ? OR s.qualified_name LIKE ? ESCAPE '\'
		ORDER BY s.kind, f.path, s.line
		LIMIT 50
	`, input.Name, input.Name, "%::"+escaped)
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
