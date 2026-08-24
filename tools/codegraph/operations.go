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
	scanRoots := []string{root}
	if len(input.Roots) > 0 {
		scanRoots = nil
		seenRoots := make(map[string]bool)
		for index, sourceRoot := range input.Roots {
			sourceRoot = filepath.Clean(sourceRoot)
			if !filepath.IsAbs(sourceRoot) {
				return "", fmt.Errorf("roots[%d] must be absolute", index)
			}
			if err := validateCodeGraphRoot(sourceRoot); err != nil {
				return "", fmt.Errorf("roots[%d]: %w", index, err)
			}
			key := strings.ToLower(sourceRoot)
			if !seenRoots[key] {
				seenRoots[key] = true
				scanRoots = append(scanRoots, sourceRoot)
			}
		}
	}

	existingDB, existingDBErr := os.Stat(filepath.Join(root, dbFileName))
	compactRefresh := existingDBErr == nil && existingDB.Size() >= 32*1024*1024
	db, err := openDB(root)
	if err != nil {
		return "", fmt.Errorf("db: %w", err)
	}
	defer db.Close()
	fullRefresh, err := prepareExtractorVersion(db)
	if err != nil {
		return "", fmt.Errorf("prepare extractor version: %w", err)
	}

	var indexed, skipped, removed int
	var indexedAtomic, skippedAtomic, errorsAtomic int64
	var errorMu sync.Mutex
	var errorDetails []string
	var scanElapsed, parseStoreElapsed, semanticElapsed time.Duration
	addError := func(path string, err error) {
		atomic.AddInt64(&errorsAtomic, 1)
		errorMu.Lock()
		defer errorMu.Unlock()
		if len(errorDetails) >= 10 {
			return
		}
		if path == "" {
			errorDetails = append(errorDetails, err.Error())
			return
		}
		errorDetails = append(errorDetails, fmt.Sprintf("%s: %v", path, err))
	}
	t0 := time.Now()

	// Phase 1: collect files to index
	type fileEntry struct {
		path string
		lang string
		root string
	}
	var files []fileEntry
	seenFiles := make(map[string]struct{})
	walkHadErrors := false

	for _, scanRoot := range scanRoots {
		gitIgnore := loadGitignore(scanRoot)
		walkErr := filepath.Walk(scanRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				walkHadErrors = true
				addError(path, err)
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
					rel, err := filepath.Rel(scanRoot, path)
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
				rel, err := filepath.Rel(scanRoot, path)
				if err == nil && gitIgnore.match(rel, false) {
					return nil
				}
			}
			seenFiles[path] = struct{}{}
			changed, changeErr := isFileChanged(db, path)
			if changeErr != nil {
				addError(path, fmt.Errorf("change detection: %w", changeErr))
				changed = true
			}
			if !changed {
				atomic.AddInt64(&skippedAtomic, 1)
				return nil
			}
			files = append(files, fileEntry{path: path, lang: lang, root: scanRoot})
			return nil
		})
		if walkErr != nil {
			walkHadErrors = true
			addError(scanRoot, fmt.Errorf("walk: %w", walkErr))
		}
	}

	// Reconcile the index with the current source set. Skip this after an
	// incomplete walk so a transient permission error cannot purge valid data.
	if !walkHadErrors {
		removed, err = purgeStaleFiles(db, seenFiles)
		if err != nil {
			addError(root, fmt.Errorf("purge stale files: %w", err))
		}
	}
	scanElapsed = time.Since(t0)

	// Phase 2: parallel parse + sequential DB store
	type parseJob struct {
		path   string
		lang   string
		root   string
		hash   string
		result *ParseResult
	}

	resultsCh := make(chan parseJob, 64)
	var wg sync.WaitGroup

	// Worker goroutines for parsing
	numWorkers := poolSize
	if w, _ := common.FlexInt(input.Workers); w > 0 {
		numWorkers = w
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
					addError(f.path, fmt.Errorf("read: %w", err))
					continue
				}
				result, err := parseSource(f.lang, string(data))
				if err != nil {
					addError(f.path, fmt.Errorf("parse: %w", err))
					continue
				}
				resultsCh <- parseJob{path: f.path, lang: f.lang, root: f.root, hash: contentHash(data), result: result}
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
	conditionCache := make(map[string]any)

	flushBatch := func() {
		if len(batch) == 0 {
			return
		}
		tx, err := db.Begin()
		if err != nil {
			for _, job := range batch {
				addError(job.path, fmt.Errorf("begin index transaction: %w", err))
			}
			batch = batch[:0]
			return
		}
		var committed int64
		for i, job := range batch {
			savepoint := fmt.Sprintf("codegraph_file_%d", i)
			if err := storeParseResultTxAtomicHashWithWorkspace(tx, savepoint, job.path, job.lang, job.hash, job.root, job.result, conditionCache); err != nil {
				addError(job.path, fmt.Errorf("store index: %w", err))
				continue
			}
			committed++
		}
		if err := tx.Commit(); err != nil {
			// Commit failed = all rolled back, count all as errors
			for _, job := range batch {
				addError(job.path, fmt.Errorf("commit index transaction: %w", err))
			}
			_ = tx.Rollback()
			conditionCache = make(map[string]any)
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
	parseStoreElapsed = time.Since(t0) - scanElapsed
	graphChanged := fullRefresh || removed > 0 || atomic.LoadInt64(&indexedAtomic) > 0
	if graphChanged {
		semanticStart := time.Now()
		if err := resolveSymbolKinds(db); err != nil {
			addError(root, fmt.Errorf("resolve symbol kinds: %w", err))
		}
		if err := resolveCallCandidates(db); err != nil {
			addError(root, fmt.Errorf("resolve call candidates: %w", err))
		}
		if fullRefresh && compactRefresh {
			if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
				addError(root, fmt.Errorf("checkpoint refreshed index: %w", err))
			}
			if _, err := db.Exec("VACUUM"); err != nil {
				addError(root, fmt.Errorf("compact refreshed index: %w", err))
			}
		}
		_, _ = db.Exec("PRAGMA optimize")
		semanticElapsed = time.Since(semanticStart)
	}

	indexed = int(indexedAtomic)
	skipped = int(skippedAtomic)
	errors := int(errorsAtomic)

	elapsed := time.Since(t0)
	result := fmt.Sprintf("Index complete: %d files indexed, %d unchanged (skipped), %d removed, %d errors\nTime: %s\nDB: %s",
		indexed, skipped, removed, errors, elapsed.Round(time.Millisecond), filepath.Join(root, dbFileName))
	if fullRefresh {
		result += "\nExtractor: v" + extractorVersion + " (full structural refresh)"
	}
	if graphChanged {
		result += fmt.Sprintf("\nPhases: scan %s, parse/store %s, semantic %s", scanElapsed.Round(time.Millisecond), parseStoreElapsed.Round(time.Millisecond), semanticElapsed.Round(time.Millisecond))
	}
	if len(errorDetails) > 0 {
		result += "\nErrors:\n  " + strings.Join(errorDetails, "\n  ")
		if errors > len(errorDetails) {
			result += fmt.Sprintf("\n  ... and %d more", errors-len(errorDetails))
		}
	}
	return result, nil
}

func validateCodeGraphRoot(root string) error {
	if err := common.CheckDangerousPath(root); err != nil {
		return err
	}
	if !common.GetAllowSymlinks() {
		if info, err := os.Lstat(root); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlinks are not allowed (see set_config allow_symlinks)")
		}
	}
	info, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("cannot access path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path must be a directory")
	}
	return nil
}

// purgeStaleFiles removes indexed files that are no longer part of the current
// source walk. Foreign-key cascades remove their symbols and relationships.
func purgeStaleFiles(db *sql.DB, seen map[string]struct{}) (int, error) {
	rows, err := db.Query("SELECT id, path FROM files")
	if err != nil {
		return 0, err
	}
	var staleIDs []int64
	for rows.Next() {
		var id int64
		var path string
		if err := rows.Scan(&id, &path); err != nil {
			rows.Close()
			return 0, err
		}
		if _, ok := seen[path]; !ok {
			staleIDs = append(staleIDs, id)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	if len(staleIDs) == 0 {
		return 0, nil
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	stmt, err := tx.Prepare("DELETE FROM files WHERE id = ?")
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	for _, id := range staleIDs {
		if _, err := stmt.Exec(id); err != nil {
			stmt.Close()
			tx.Rollback()
			return 0, err
		}
	}
	if err := stmt.Close(); err != nil {
		tx.Rollback()
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(staleIDs), nil
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
			SELECT s.name, s.qualified_name, s.kind, f.path, s.line, s.end_line, s.scope, s.signature, s.return_type, COALESCE(cond.expression,s.condition)
			FROM symbols s JOIN files f ON s.file_id = f.id LEFT JOIN conditions cond ON cond.id=s.condition_id
			WHERE s.name LIKE ? ESCAPE '\' OR s.qualified_name LIKE ? ESCAPE '\'
			ORDER BY s.kind, f.path, s.line
			LIMIT 50
		`, likePattern, likePattern)
	} else {
		// Exact mode (existing behavior)
		escaped := escapeLike(input.Name)
		rows, err = db.Query(`
			SELECT s.name, s.qualified_name, s.kind, f.path, s.line, s.end_line, s.scope, s.signature, s.return_type, COALESCE(cond.expression,s.condition)
			FROM symbols s JOIN files f ON s.file_id = f.id LEFT JOIN conditions cond ON cond.id=s.condition_id
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
		var name, qn, kind, path, scope, signature, returnType, condition string
		var line, endLine int
		if err := rows.Scan(&name, &qn, &kind, &path, &line, &endLine, &scope, &signature, &returnType, &condition); err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("[%s] %s  %s:%d-%d", kind, qn, path, line, max(line, endLine)))
		if scope != "" {
			sb.WriteString(fmt.Sprintf("  (scope: %s)", scope))
		}
		if signature != "" {
			sb.WriteString(fmt.Sprintf("  %s", signature))
		}
		if returnType != "" {
			sb.WriteString(fmt.Sprintf("  (returns: %s)", returnType))
		}
		if condition != "" {
			sb.WriteString(fmt.Sprintf("  [if %s]", condition))
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
		SELECT COALESCE(NULLIF(c.raw_text, ''), c.callee_name), f.path, c.caller_line,
		       COALESCE(NULLIF(c.caller_qualified_name, ''), c.scope), c.resolution, c.confidence, c.target_kind
		FROM calls c JOIN files f ON c.caller_file_id = f.id
		WHERE c.callee_name = ? OR c.callee_qualified_name = ? OR c.raw_text = ?
		   OR EXISTS (
		       SELECT 1 FROM call_candidates cc JOIN symbols target ON target.id = cc.symbol_id
		       WHERE cc.call_id = c.id AND (target.name = ? OR target.qualified_name = ?)
		   )
		   OR EXISTS (
		       SELECT 1 FROM dispatch_edges d JOIN semantic_symbols target ON target.id=d.semantic_id
		       WHERE d.call_id=c.id AND (target.name=? OR target.qualified_name=?)
		   )
		ORDER BY f.path, c.caller_line
		LIMIT 100
	`, input.Name, input.Name, input.Name, input.Name, input.Name, input.Name, input.Name)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var sb strings.Builder
	count := 0
	for rows.Next() {
		var callee, path, scope, resolution, targetKind string
		var line int
		var confidence float64
		if err := rows.Scan(&callee, &path, &line, &scope, &resolution, &confidence, &targetKind); err != nil {
			continue
		}
		label := resolution
		if targetKind != "" && targetKind != "internal" && targetKind != "unresolved" {
			label = targetKind + "/" + resolution
		}
		sb.WriteString(fmt.Sprintf("  %s:%d  calls %s [%s %.2f]", path, line, callee, label, confidence))
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
		SELECT s.file_id, s.line, CASE WHEN s.end_line >= s.line THEN s.end_line ELSE COALESCE(
			(SELECT MIN(s2.line) - 1 FROM symbols s2 WHERE s2.file_id = s.file_id AND s2.line > s.line AND s2.kind IN ('function','method')),
			s.line + 1000
		) END
		FROM symbols s
		WHERE (s.name = ? OR s.qualified_name = ? OR s.qualified_name LIKE ? ESCAPE '\') AND s.kind IN ('function','method')
		LIMIT 1
	`, input.Name, input.Name, "%::"+escaped).Scan(&fileID, &startLine, &endLine)
	if err != nil {
		return fmt.Sprintf("Symbol %q not found in index.", input.Name), nil
	}

	rows, err := db.Query(`
		SELECT COALESCE(NULLIF(c.raw_text, ''), c.callee_name), c.caller_line, c.resolution, c.confidence, c.target_kind,
		       (SELECT COUNT(*) FROM dispatch_edges d WHERE d.call_id=c.id)
		FROM calls c
		WHERE c.caller_file_id = ? AND c.caller_line >= ? AND c.caller_line <= ?
		ORDER BY c.caller_line
		LIMIT ? OFFSET ?
	`, fileID, startLine, endLine, input.MaxResults+1, input.Offset)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var sb strings.Builder
	usedChars := 0
	common.AppendWithinRuneBudget(&sb, &usedChars, fmt.Sprintf("Callees of %q (offset:%d, max:%d):\n", input.Name, input.Offset, input.MaxResults), input.MaxOutputChars)
	count := 0
	hasMore := false
	for rows.Next() {
		var callee, resolution, targetKind string
		var line, dispatchTargets int
		var confidence float64
		if err := rows.Scan(&callee, &line, &resolution, &confidence, &targetKind, &dispatchTargets); err != nil {
			continue
		}
		if count >= input.MaxResults {
			hasMore = true
			break
		}
		label := resolution
		if targetKind != "" && targetKind != "internal" && targetKind != "unresolved" {
			label = targetKind + "/" + resolution
		}
		if dispatchTargets > 0 {
			label += fmt.Sprintf(" dynamic:1+%d", dispatchTargets)
		}
		entry, _ := common.TruncateRunes(fmt.Sprintf("  line:%d  %s [%s %.2f]\n", line, callee, label, confidence), min(input.MaxOutputChars/2, 10000), "…\n")
		if !common.AppendWithinRuneBudget(&sb, &usedChars, entry, input.MaxOutputChars) {
			hasMore = true
			break
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("query error: %w", err)
	}

	if count == 0 {
		return fmt.Sprintf("No callees found for %q at offset %d.", input.Name, input.Offset), nil
	}
	if hasMore {
		fmt.Fprintf(&sb, "\n[More callees available; retry with offset=%d.]\n", input.Offset+count)
	}
	result, _ := common.TruncateRunes(sb.String(), input.MaxOutputChars, fmt.Sprintf("\n[Output truncated; retry with offset=%d]", input.Offset+count))
	return result, nil
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

	result, err := parseSource(lang, string(data))
	if err != nil {
		return "", fmt.Errorf("parse failed: %w", err)
	}

	type outputEntry struct {
		section string
		text    string
	}
	var entries []outputEntry

	if len(result.Classes) > 0 {
		for _, s := range result.Classes {
			scope := ""
			if s.Scope != "" {
				scope = fmt.Sprintf(" (scope: %s)", s.Scope)
			}
			kind := s.Kind
			if kind == "" {
				kind = s.NodeType
			}
			entries = append(entries, outputEntry{"Types", fmt.Sprintf("  %s %s  line:%d%s%s\n", kind, s.Name, s.Line, scope, conditionAnnotation(s.Condition))})
		}
	}

	if len(result.Functions) > 0 {
		for _, s := range result.Functions {
			scope := ""
			if s.Scope != "" {
				scope = fmt.Sprintf(" (scope: %s)", s.Scope)
			}
			parent := ""
			if s.Parent == "field_declaration_list" {
				parent = " [inline]"
			}
			name := cleanSymbolName(s.Name)
			if s.QualifiedName != "" {
				name = s.QualifiedName
			}
			returns := ""
			if s.ReturnType != "" {
				returns = " -> " + s.ReturnType
			}
			entries = append(entries, outputEntry{"Functions/Methods", fmt.Sprintf("  %s%s  line:%d-%d%s%s%s\n", name, returns, s.Line, max(s.Line, s.EndLine), scope, parent, conditionAnnotation(s.Condition))})
		}
	}

	if len(result.Imports) > 0 {
		for _, s := range result.Imports {
			entries = append(entries, outputEntry{"Imports/Includes", fmt.Sprintf("  %s  line:%d%s\n", s.Name, s.Line, conditionAnnotation(s.Condition))})
		}
	}

	if len(result.Inheritance) > 0 {
		for _, inh := range result.Inheritance {
			kind := inh.Kind
			if kind == "" {
				kind = "inherits"
			}
			entries = append(entries, outputEntry{"Relations", fmt.Sprintf("  %s -[%s]-> %s  line:%d\n", inh.ClassName, kind, inh.ParentName, inh.Line)})
		}
	}

	if len(result.Calls) > 0 {
		callCount := len(result.Calls)
		for _, s := range result.Calls {
			if s.Capture == "callee" {
				scope := ""
				if s.Scope != "" {
					scope = fmt.Sprintf(" (in: %s)", s.Scope)
				}
				callee := s.RawText
				if callee == "" {
					callee = cleanSymbolName(s.Name)
				}
				entries = append(entries, outputEntry{fmt.Sprintf("Calls (%d)", callCount), fmt.Sprintf("  %s  line:%d%s [%s %.2f]%s\n", callee, s.Line, scope, s.Resolution, s.Confidence, conditionAnnotation(s.Condition))})
			}
		}
	}

	start := input.Offset
	if start > len(entries) {
		start = len(entries)
	}
	var sb strings.Builder
	usedChars := 0
	headerPath, _ := common.TruncateRunes(path, 2000, "…")
	common.AppendWithinRuneBudget(&sb, &usedChars, fmt.Sprintf("File: %s\nSymbols: %d (offset:%d, max:%d)\n\n", headerPath, len(entries), start, input.MaxResults), input.MaxOutputChars)
	shown := 0
	lastSection := ""
	for _, entry := range entries[start:] {
		if shown >= input.MaxResults {
			break
		}
		line, _ := common.TruncateRunes(entry.text, min(input.MaxOutputChars/2, 10000), "…\n")
		fragment := ""
		if entry.section != lastSection {
			fragment = entry.section + ":\n"
		}
		fragment += line
		if !common.AppendWithinRuneBudget(&sb, &usedChars, fragment, input.MaxOutputChars) {
			break
		}
		lastSection = entry.section
		shown++
	}
	if start+shown < len(entries) {
		fmt.Fprintf(&sb, "\n[More symbols available; retry with offset=%d.]\n", start+shown)
	}
	resultText, _ := common.TruncateRunes(sb.String(), input.MaxOutputChars, fmt.Sprintf("\n[Output truncated; retry with offset=%d]", start+shown))
	return resultText, nil
}

func conditionAnnotation(condition string) string {
	if condition == "" {
		return ""
	}
	return " [if " + condition + "]"
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
		SELECT s.name, s.qualified_name, f.path, s.line, s.end_line, s.signature
		FROM symbols s JOIN files f ON s.file_id = f.id
		WHERE s.kind IN ('method','property') AND (s.scope = ? OR s.qualified_name LIKE ? ESCAPE '\')
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
		var name, qn, path, signature string
		var line, endLine int
		if err := rows.Scan(&name, &qn, &path, &line, &endLine, &signature); err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %s  %s:%d-%d", qn, path, line, max(line, endLine)))
		if signature != "" {
			sb.WriteString("  " + signature)
		}
		sb.WriteString("\n")
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
		SELECT i.parent_name, i.relation_kind, f.path, i.line
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
		var parent, relation, path string
		var line int
		if err := rows.Scan(&parent, &relation, &path, &line); err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("  [%s] %s  (%s:%d)\n", relation, parent, path, line))
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
		SELECT i.class_name, i.relation_kind, f.path, i.line
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
		var child, relation, path string
		var line int
		if err := rows2.Scan(&child, &relation, &path, &line); err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("  [%s] %s  (%s:%d)\n", relation, child, path, line))
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

	var files, types, functions, methods, calls, candidates, includes, inheritance, variables, macros int
	var semanticSymbols, aliases, transitiveIncludes, dispatchEdges, conditionalFacts int
	var internalExact, internalCandidate, externalCalls, macroCalls, callbackCalls, unresolvedCalls int
	db.QueryRow("SELECT COUNT(*) FROM files").Scan(&files)
	db.QueryRow("SELECT COUNT(*) FROM symbols WHERE kind IN ('class','struct','interface','trait','enum','union','record','type','alias','impl')").Scan(&types)
	db.QueryRow("SELECT COUNT(*) FROM symbols WHERE kind='function'").Scan(&functions)
	db.QueryRow("SELECT COUNT(*) FROM symbols WHERE kind='method'").Scan(&methods)
	db.QueryRow("SELECT COUNT(*) FROM calls").Scan(&calls)
	db.QueryRow("SELECT COUNT(*) FROM call_candidates").Scan(&candidates)
	db.QueryRow("SELECT COUNT(*) FROM includes").Scan(&includes)
	db.QueryRow("SELECT COUNT(*) FROM inheritance").Scan(&inheritance)
	db.QueryRow("SELECT COUNT(*) FROM variables").Scan(&variables)
	db.QueryRow("SELECT COUNT(*) FROM macros").Scan(&macros)
	db.QueryRow("SELECT COUNT(*) FROM semantic_symbols").Scan(&semanticSymbols)
	db.QueryRow("SELECT COUNT(*) FROM type_aliases").Scan(&aliases)
	db.QueryRow("SELECT COUNT(*) FROM include_edges WHERE distance>1").Scan(&transitiveIncludes)
	db.QueryRow("SELECT COUNT(*) FROM dispatch_edges").Scan(&dispatchEdges)
	db.QueryRow("SELECT (SELECT COUNT(*) FROM symbols WHERE condition<>'' OR condition_id IS NOT NULL) + (SELECT COUNT(*) FROM calls WHERE condition<>'' OR condition_id IS NOT NULL) + (SELECT COUNT(*) FROM includes WHERE condition<>'' OR condition_id IS NOT NULL)").Scan(&conditionalFacts)
	db.QueryRow("SELECT COUNT(*) FROM calls WHERE target_kind='internal' AND resolution='exact'").Scan(&internalExact)
	db.QueryRow("SELECT COUNT(*) FROM calls WHERE target_kind='internal' AND resolution<>'exact'").Scan(&internalCandidate)
	db.QueryRow("SELECT COUNT(*) FROM calls WHERE target_kind='external'").Scan(&externalCalls)
	db.QueryRow("SELECT COUNT(*) FROM calls WHERE target_kind='macro'").Scan(&macroCalls)
	db.QueryRow("SELECT COUNT(*) FROM calls WHERE target_kind='callback'").Scan(&callbackCalls)
	db.QueryRow("SELECT COUNT(*) FROM calls WHERE target_kind='unresolved'").Scan(&unresolvedCalls)

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

	unresolvedRate := 0.0
	if calls > 0 {
		unresolvedRate = float64(unresolvedCalls) * 100 / float64(calls)
	}
	return fmt.Sprintf("Project Index Stats:\n  Files: %d\n  Types: %d\n  Semantic symbols: %d\n  Functions: %d\n  Methods: %d\n  Variables/Fields: %d\n  Type aliases: %d\n  Macros: %d\n  Call sites: %d\n  Candidate edges: %d\n  Dynamic dispatch edges: %d\n  Imports/Includes: %d (transitive: %d)\n  Type relations: %d\n  Conditional facts: %d\n\nCall Classification:\n  Internal exact: %d\n  Internal candidate: %d\n  External: %d\n  Macro use: %d\n  Callback: %d\n  Truly unresolved: %d (%.2f%%)\n\nLanguages:\n%s",
		files, types, semanticSymbols, functions, methods, variables, aliases, macros, calls, candidates, dispatchEdges, includes, transitiveIncludes, inheritance, conditionalFacts,
		internalExact, internalCandidate, externalCalls, macroCalls, callbackCalls, unresolvedCalls, unresolvedRate, langBreakdown.String()), nil
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

	// A symbol is considered used by either a direct qualified edge or any
	// conservative candidate edge. This avoids false "unused" reports when a
	// short call name is ambiguous.
	rows, err := db.Query(`
		SELECT s.name, s.qualified_name, s.kind, f.path, s.line, s.scope
		FROM symbols s
		JOIN files f ON s.file_id = f.id
		WHERE s.kind IN ('function', 'method')
		  AND NOT EXISTS (SELECT 1 FROM calls c WHERE c.resolution = 'exact' AND c.callee_qualified_name = s.qualified_name)
		  AND NOT EXISTS (SELECT 1 FROM call_candidates cc WHERE cc.symbol_id = s.id)
		  AND NOT EXISTS (SELECT 1 FROM symbol_occurrences so JOIN dispatch_edges d ON d.semantic_id=so.semantic_id WHERE so.symbol_id=s.id)
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

	maxDepth, _ := common.FlexInt(input.Depth)
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
			SELECT DISTINCT COALESCE(NULLIF(c.caller_qualified_name, ''), c.scope), f.path, c.caller_line
			FROM calls c JOIN files f ON c.caller_file_id = f.id
			WHERE c.callee_name = ? OR c.callee_qualified_name = ? OR c.raw_text = ?
			   OR EXISTS (
			       SELECT 1 FROM call_candidates cc JOIN symbols target ON target.id = cc.symbol_id
			       WHERE cc.call_id = c.id AND (target.name = ? OR target.qualified_name = ?)
			   )
			   OR EXISTS (
			       SELECT 1 FROM dispatch_edges d JOIN semantic_symbols target ON target.id=d.semantic_id
			       WHERE d.call_id=c.id AND (target.name=? OR target.qualified_name=?)
			   )
			ORDER BY f.path, c.caller_line
			LIMIT 50
		`, name, name, name, name, name, name, name)
	} else {
		// Find callees: first find this function's file and line range
		var fileID, startLine, endLine int
		escaped := escapeLike(name)
		err = db.QueryRow(`
			SELECT s.file_id, s.line, CASE WHEN s.end_line >= s.line THEN s.end_line ELSE COALESCE(
				(SELECT MIN(s2.line) - 1 FROM symbols s2 WHERE s2.file_id = s.file_id AND s2.line > s.line AND s2.kind IN ('function','method')),
				s.line + 1000
			) END
			FROM symbols s
			WHERE (s.name = ? OR s.qualified_name = ? OR s.qualified_name LIKE ? ESCAPE '\') AND s.kind IN ('function','method')
			LIMIT 1
		`, name, name, "%::"+escaped).Scan(&fileID, &startLine, &endLine)
		if err != nil {
			return
		}
		rows, err = db.Query(`
			SELECT DISTINCT COALESCE(NULLIF(c.raw_text, ''), c.callee_name), f.path, c.caller_line
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
