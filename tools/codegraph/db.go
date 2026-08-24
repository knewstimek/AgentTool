package codegraph

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const dbFileName = ".codegraph.db"
const extractorVersion = "10"

const schemaSQL = `
CREATE TABLE IF NOT EXISTS files (
	id INTEGER PRIMARY KEY,
	path TEXT NOT NULL UNIQUE,
	hash TEXT NOT NULL,
	language TEXT NOT NULL,
	source_root TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS conditions (
	id INTEGER PRIMARY KEY,
	expression TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS symbols (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	qualified_name TEXT NOT NULL,
	kind TEXT NOT NULL,
	file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
	line INTEGER NOT NULL,
	end_line INTEGER NOT NULL DEFAULT 0,
	col INTEGER NOT NULL,
	scope TEXT NOT NULL DEFAULT '',
	parent_kind TEXT NOT NULL DEFAULT '',
	signature TEXT NOT NULL DEFAULT '',
	arity INTEGER NOT NULL DEFAULT -1,
	parameter_types TEXT NOT NULL DEFAULT '',
	return_type TEXT NOT NULL DEFAULT '',
	semantic_key TEXT NOT NULL DEFAULT '',
	modifiers TEXT NOT NULL DEFAULT '',
	condition TEXT NOT NULL DEFAULT '',
	condition_id INTEGER REFERENCES conditions(id) ON DELETE SET NULL,
	UNIQUE(qualified_name, file_id, line)
);

CREATE TABLE IF NOT EXISTS calls (
	id INTEGER PRIMARY KEY,
	caller_file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
	caller_line INTEGER NOT NULL,
	callee_name TEXT NOT NULL,
	scope TEXT NOT NULL DEFAULT '',
	caller_qualified_name TEXT NOT NULL DEFAULT '',
	callee_qualified_name TEXT NOT NULL DEFAULT '',
	raw_text TEXT NOT NULL DEFAULT '',
	receiver TEXT NOT NULL DEFAULT '',
	resolution TEXT NOT NULL DEFAULT 'unresolved',
	confidence REAL NOT NULL DEFAULT 0.20,
	arity INTEGER NOT NULL DEFAULT -1,
	argument_types TEXT NOT NULL DEFAULT '',
	argument_expressions TEXT NOT NULL DEFAULT '',
	receiver_type TEXT NOT NULL DEFAULT '',
	condition TEXT NOT NULL DEFAULT '',
	condition_id INTEGER REFERENCES conditions(id) ON DELETE SET NULL,
	target_kind TEXT NOT NULL DEFAULT 'unresolved'
);

CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_symbols_qn ON symbols(qualified_name);
CREATE INDEX IF NOT EXISTS idx_symbols_kind ON symbols(kind);
CREATE INDEX IF NOT EXISTS idx_symbols_file ON symbols(file_id);
CREATE INDEX IF NOT EXISTS idx_calls_callee ON calls(callee_name);
CREATE INDEX IF NOT EXISTS idx_calls_file ON calls(caller_file_id);

CREATE TABLE IF NOT EXISTS call_candidates (
	call_id INTEGER NOT NULL REFERENCES calls(id) ON DELETE CASCADE,
	symbol_id INTEGER NOT NULL REFERENCES symbols(id) ON DELETE CASCADE,
	confidence REAL NOT NULL,
	basis TEXT NOT NULL,
	semantic_id INTEGER REFERENCES semantic_symbols(id) ON DELETE SET NULL,
	evidence TEXT NOT NULL DEFAULT '',
	PRIMARY KEY(call_id, symbol_id)
);

CREATE INDEX IF NOT EXISTS idx_call_candidates_symbol ON call_candidates(symbol_id);

CREATE TABLE IF NOT EXISTS inheritance (
	id INTEGER PRIMARY KEY,
	class_name TEXT NOT NULL,
	parent_name TEXT NOT NULL,
	file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
	line INTEGER NOT NULL,
	relation_kind TEXT NOT NULL DEFAULT 'inherits'
);

CREATE INDEX IF NOT EXISTS idx_inh_class ON inheritance(class_name);
CREATE INDEX IF NOT EXISTS idx_inh_parent ON inheritance(parent_name);

CREATE TABLE IF NOT EXISTS includes (
	id INTEGER PRIMARY KEY,
	file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
	included TEXT NOT NULL,
	line INTEGER NOT NULL,
	resolved_file_id INTEGER REFERENCES files(id) ON DELETE SET NULL,
	condition TEXT NOT NULL DEFAULT '',
	condition_id INTEGER REFERENCES conditions(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_includes_file ON includes(file_id);
CREATE INDEX IF NOT EXISTS idx_includes_included ON includes(included);

CREATE TABLE IF NOT EXISTS variables (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	qualified_name TEXT NOT NULL DEFAULT '',
	type_name TEXT NOT NULL DEFAULT '',
	owner TEXT NOT NULL DEFAULT '',
	kind TEXT NOT NULL,
	target TEXT NOT NULL DEFAULT '',
	type_arguments TEXT NOT NULL DEFAULT '',
	condition TEXT NOT NULL DEFAULT '',
	condition_id INTEGER REFERENCES conditions(id) ON DELETE SET NULL,
	file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
	line INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_variables_name ON variables(name);
CREATE INDEX IF NOT EXISTS idx_variables_owner ON variables(owner);
CREATE INDEX IF NOT EXISTS idx_variables_type ON variables(type_name);

CREATE TABLE IF NOT EXISTS macros (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	qualified_name TEXT NOT NULL DEFAULT '',
	body TEXT NOT NULL DEFAULT '',
	function_like INTEGER NOT NULL DEFAULT 0,
	arity INTEGER NOT NULL DEFAULT -1,
	file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
	line INTEGER NOT NULL,
	condition TEXT NOT NULL DEFAULT '',
	condition_id INTEGER REFERENCES conditions(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_macros_name ON macros(name);

CREATE TABLE IF NOT EXISTS macro_uses (
	call_id INTEGER PRIMARY KEY REFERENCES calls(id) ON DELETE CASCADE,
	macro_id INTEGER REFERENCES macros(id) ON DELETE SET NULL,
	name TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_macro_uses_macro ON macro_uses(macro_id);

CREATE TABLE IF NOT EXISTS callback_edges (
	call_id INTEGER PRIMARY KEY REFERENCES calls(id) ON DELETE CASCADE,
	symbol_id INTEGER REFERENCES symbols(id) ON DELETE SET NULL,
	target TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_callback_edges_symbol ON callback_edges(symbol_id);

CREATE TABLE IF NOT EXISTS type_aliases (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	qualified_name TEXT NOT NULL DEFAULT '',
	target TEXT NOT NULL,
	owner TEXT NOT NULL DEFAULT '',
	kind TEXT NOT NULL DEFAULT 'alias',
	type_parameters TEXT NOT NULL DEFAULT '',
	condition TEXT NOT NULL DEFAULT '',
	condition_id INTEGER REFERENCES conditions(id) ON DELETE SET NULL,
	file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
	line INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_type_aliases_name ON type_aliases(name);
CREATE INDEX IF NOT EXISTS idx_type_aliases_owner ON type_aliases(owner);

CREATE TABLE IF NOT EXISTS semantic_symbols (
	id INTEGER PRIMARY KEY,
	semantic_key TEXT NOT NULL UNIQUE,
	name TEXT NOT NULL,
	qualified_name TEXT NOT NULL,
	kind TEXT NOT NULL,
	language TEXT NOT NULL,
	arity INTEGER NOT NULL DEFAULT -1,
	parameter_types TEXT NOT NULL DEFAULT '',
	return_type TEXT NOT NULL DEFAULT '',
	modifiers TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_semantic_symbols_name ON semantic_symbols(name);
CREATE INDEX IF NOT EXISTS idx_semantic_symbols_qn ON semantic_symbols(qualified_name);

CREATE TABLE IF NOT EXISTS symbol_occurrences (
	semantic_id INTEGER NOT NULL REFERENCES semantic_symbols(id) ON DELETE CASCADE,
	symbol_id INTEGER NOT NULL REFERENCES symbols(id) ON DELETE CASCADE,
	role TEXT NOT NULL DEFAULT 'declaration',
	PRIMARY KEY(semantic_id, symbol_id)
);

CREATE INDEX IF NOT EXISTS idx_symbol_occurrences_symbol ON symbol_occurrences(symbol_id);

CREATE TABLE IF NOT EXISTS include_edges (
	file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
	included_file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
	distance INTEGER NOT NULL,
	condition TEXT NOT NULL DEFAULT '',
	condition_id INTEGER REFERENCES conditions(id) ON DELETE SET NULL,
	PRIMARY KEY(file_id, included_file_id)
);

CREATE INDEX IF NOT EXISTS idx_include_edges_target ON include_edges(included_file_id);
CREATE INDEX IF NOT EXISTS idx_conditions_expression ON conditions(expression);

CREATE TABLE IF NOT EXISTS dispatch_edges (
	call_id INTEGER NOT NULL REFERENCES calls(id) ON DELETE CASCADE,
	semantic_id INTEGER NOT NULL REFERENCES semantic_symbols(id) ON DELETE CASCADE,
	dispatch_kind TEXT NOT NULL,
	confidence REAL NOT NULL,
	basis TEXT NOT NULL DEFAULT '',
	PRIMARY KEY(call_id, semantic_id)
);

CREATE INDEX IF NOT EXISTS idx_dispatch_edges_semantic ON dispatch_edges(semantic_id);

CREATE TABLE IF NOT EXISTS codegraph_meta (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

// openDB opens or creates the codegraph database at the project root.
func openDB(projectRoot string) (*sql.DB, error) {
	dbPath := filepath.Join(projectRoot, dbFileName)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// WAL mode for concurrent reads
	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA foreign_keys=ON")
	// Case-sensitive LIKE to avoid matching checkDangerousPath when searching CheckDangerousPath
	db.Exec("PRAGMA case_sensitive_like=ON")

	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	if err := migrateSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}

	return db, nil
}

func migrateSchema(db *sql.DB) error {
	columns := []struct {
		table string
		name  string
		ddl   string
	}{
		{"symbols", "end_line", "INTEGER NOT NULL DEFAULT 0"},
		{"files", "source_root", "TEXT NOT NULL DEFAULT ''"},
		{"symbols", "signature", "TEXT NOT NULL DEFAULT ''"},
		{"symbols", "arity", "INTEGER NOT NULL DEFAULT -1"},
		{"symbols", "parameter_types", "TEXT NOT NULL DEFAULT ''"},
		{"symbols", "return_type", "TEXT NOT NULL DEFAULT ''"},
		{"symbols", "semantic_key", "TEXT NOT NULL DEFAULT ''"},
		{"symbols", "modifiers", "TEXT NOT NULL DEFAULT ''"},
		{"symbols", "condition", "TEXT NOT NULL DEFAULT ''"},
		{"symbols", "condition_id", "INTEGER REFERENCES conditions(id) ON DELETE SET NULL"},
		{"calls", "caller_qualified_name", "TEXT NOT NULL DEFAULT ''"},
		{"calls", "callee_qualified_name", "TEXT NOT NULL DEFAULT ''"},
		{"calls", "raw_text", "TEXT NOT NULL DEFAULT ''"},
		{"calls", "receiver", "TEXT NOT NULL DEFAULT ''"},
		{"calls", "resolution", "TEXT NOT NULL DEFAULT 'lexical'"},
		{"calls", "confidence", "REAL NOT NULL DEFAULT 0.35"},
		{"calls", "arity", "INTEGER NOT NULL DEFAULT -1"},
		{"calls", "argument_types", "TEXT NOT NULL DEFAULT ''"},
		{"calls", "argument_expressions", "TEXT NOT NULL DEFAULT ''"},
		{"calls", "receiver_type", "TEXT NOT NULL DEFAULT ''"},
		{"calls", "condition", "TEXT NOT NULL DEFAULT ''"},
		{"calls", "condition_id", "INTEGER REFERENCES conditions(id) ON DELETE SET NULL"},
		{"calls", "target_kind", "TEXT NOT NULL DEFAULT 'unresolved'"},
		{"inheritance", "relation_kind", "TEXT NOT NULL DEFAULT 'inherits'"},
		{"includes", "resolved_file_id", "INTEGER REFERENCES files(id) ON DELETE SET NULL"},
		{"includes", "condition", "TEXT NOT NULL DEFAULT ''"},
		{"includes", "condition_id", "INTEGER REFERENCES conditions(id) ON DELETE SET NULL"},
		{"variables", "type_arguments", "TEXT NOT NULL DEFAULT ''"},
		{"variables", "condition", "TEXT NOT NULL DEFAULT ''"},
		{"variables", "condition_id", "INTEGER REFERENCES conditions(id) ON DELETE SET NULL"},
		{"macros", "condition", "TEXT NOT NULL DEFAULT ''"},
		{"macros", "condition_id", "INTEGER REFERENCES conditions(id) ON DELETE SET NULL"},
		{"type_aliases", "condition_id", "INTEGER REFERENCES conditions(id) ON DELETE SET NULL"},
		{"include_edges", "condition_id", "INTEGER REFERENCES conditions(id) ON DELETE SET NULL"},
		{"call_candidates", "semantic_id", "INTEGER REFERENCES semantic_symbols(id) ON DELETE SET NULL"},
		{"call_candidates", "evidence", "TEXT NOT NULL DEFAULT ''"},
	}
	for _, column := range columns {
		exists, err := tableHasColumn(db, column.table, column.name)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", column.table, column.name, column.ddl)); err != nil {
			return fmt.Errorf("add %s.%s: %w", column.table, column.name, err)
		}
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_calls_qn ON calls(callee_qualified_name)"); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_calls_target_kind ON calls(target_kind)"); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_symbols_semantic_key ON symbols(semantic_key)"); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_includes_resolved ON includes(resolved_file_id)"); err != nil {
		return err
	}
	for _, statement := range []string{
		"CREATE INDEX IF NOT EXISTS idx_symbols_condition ON symbols(condition_id)",
		"CREATE INDEX IF NOT EXISTS idx_calls_condition ON calls(condition_id)",
		"CREATE INDEX IF NOT EXISTS idx_variables_condition ON variables(condition_id)",
		"CREATE INDEX IF NOT EXISTS idx_includes_condition ON includes(condition_id)",
		"CREATE INDEX IF NOT EXISTS idx_macros_condition ON macros(condition_id)",
		"CREATE INDEX IF NOT EXISTS idx_type_aliases_condition ON type_aliases(condition_id)",
		"CREATE INDEX IF NOT EXISTS idx_include_edges_condition ON include_edges(condition_id)",
	} {
		if _, err := db.Exec(statement); err != nil {
			return err
		}
	}
	_, err := db.Exec(`INSERT INTO codegraph_meta(key, value) VALUES('schema_version', '4')
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`)
	return err
}

func tableHasColumn(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, pk int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// prepareExtractorVersion forces a content refresh when extraction semantics
// change even if source files themselves did not. Failed files keep an empty
// hash and will be retried on the next index run.
func prepareExtractorVersion(db *sql.DB) (bool, error) {
	var current string
	err := db.QueryRow("SELECT value FROM codegraph_meta WHERE key='extractor_version'").Scan(&current)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	if current == extractorVersion {
		return false, nil
	}
	tx, err := db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE files SET hash=''"); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`INSERT INTO codegraph_meta(key, value) VALUES('extractor_version', ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, extractorVersion); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// fileHash returns a content hash. Metadata-only fingerprints can miss edits
// made with preserved timestamps and unchanged byte lengths.
func fileHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return contentHash(data), nil
}

func contentHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func internCondition(tx *sql.Tx, cache map[string]any, expression string) (any, error) {
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return nil, nil
	}
	if id, ok := cache[expression]; ok {
		return id, nil
	}
	var id int64
	if err := tx.QueryRow(`INSERT INTO conditions(expression) VALUES (?)
		ON CONFLICT(expression) DO UPDATE SET expression=excluded.expression RETURNING id`, expression).Scan(&id); err != nil {
		return nil, fmt.Errorf("intern condition: %w", err)
	}
	cache[expression] = id
	return id, nil
}

// storeParseResult saves parsed symbols and calls in its own transaction.
func storeParseResult(db *sql.DB, filePath, lang string, result *ParseResult) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := storeParseResultTx(tx, filePath, lang, result); err != nil {
		return err
	}
	return tx.Commit()
}

// storeParseResultTx saves parsed symbols using an existing transaction.
func storeParseResultTx(tx *sql.Tx, filePath, lang string, result *ParseResult) error {
	hash, err := fileHash(filePath)
	if err != nil {
		return err
	}
	return storeParseResultTxHash(tx, filePath, lang, hash, result)
}

// storeParseResultTxHash stores the graph together with the digest of the
// exact source bytes that were parsed by the worker.
func storeParseResultTxHash(tx *sql.Tx, filePath, lang, hash string, result *ParseResult) error {
	return storeParseResultTxHashWithConditionCache(tx, filePath, lang, hash, result, make(map[string]any))
}

func storeParseResultTxHashWithConditionCache(tx *sql.Tx, filePath, lang, hash string, result *ParseResult, conditionCache map[string]any) error {
	return storeParseResultTxHashWithWorkspace(tx, filePath, lang, hash, filepath.Dir(filePath), result, conditionCache)
}

func storeParseResultTxHashWithWorkspace(tx *sql.Tx, filePath, lang, hash, sourceRoot string, result *ParseResult, conditionCache map[string]any) error {

	// Upsert file
	var fileID int64
	row := tx.QueryRow("SELECT id FROM files WHERE path = ?", filePath)
	if err := row.Scan(&fileID); err == sql.ErrNoRows {
		res, err := tx.Exec("INSERT INTO files (path, hash, language, source_root) VALUES (?, ?, ?, ?)", filePath, hash, lang, sourceRoot)
		if err != nil {
			return err
		}
		fileID, _ = res.LastInsertId()
	} else if err != nil {
		return err
	} else {
		// File exists, clear old data and update hash
		if _, err := tx.Exec("DELETE FROM symbols WHERE file_id = ?", fileID); err != nil {
			return fmt.Errorf("delete old symbols: %w", err)
		}
		if _, err := tx.Exec("DELETE FROM calls WHERE caller_file_id = ?", fileID); err != nil {
			return fmt.Errorf("delete old calls: %w", err)
		}
		if _, err := tx.Exec("DELETE FROM inheritance WHERE file_id = ?", fileID); err != nil {
			return fmt.Errorf("delete old inheritance: %w", err)
		}
		if _, err := tx.Exec("DELETE FROM includes WHERE file_id = ?", fileID); err != nil {
			return fmt.Errorf("delete old includes: %w", err)
		}
		if _, err := tx.Exec("DELETE FROM variables WHERE file_id = ?", fileID); err != nil {
			return fmt.Errorf("delete old variables: %w", err)
		}
		if _, err := tx.Exec("DELETE FROM macros WHERE file_id = ?", fileID); err != nil {
			return fmt.Errorf("delete old macros: %w", err)
		}
		if _, err := tx.Exec("DELETE FROM type_aliases WHERE file_id = ?", fileID); err != nil {
			return fmt.Errorf("delete old type aliases: %w", err)
		}
		if _, err := tx.Exec("UPDATE files SET hash = ?, language = ?, source_root = ? WHERE id = ?", hash, lang, sourceRoot, fileID); err != nil {
			return fmt.Errorf("update file hash: %w", err)
		}
	}

	// Insert symbols
	stmtSym, err := tx.Prepare(`INSERT OR IGNORE INTO symbols
		(name, qualified_name, kind, file_id, line, end_line, col, scope, parent_kind,
		 signature, arity, parameter_types, return_type, semantic_key, modifiers, condition_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmtSym.Close()

	for _, s := range result.Classes {
		qn := s.Name
		if s.QualifiedName != "" {
			qn = s.QualifiedName
		}
		if s.Scope != "" {
			if s.QualifiedName == "" {
				qn = s.Scope + "::" + s.Name
			}
		}
		kind := s.Kind
		if kind == "" {
			kind = "class"
		}
		semanticKey := s.SemanticKey
		if semanticKey == "" {
			s.Kind, s.QualifiedName = kind, qn
			semanticKey = semanticIdentity(lang, s)
		}
		conditionID, err := internCondition(tx, conditionCache, s.Condition)
		if err != nil {
			return err
		}
		if _, err := stmtSym.Exec(s.Name, qn, kind, fileID, s.Line, s.EndLine, s.Col, s.Scope, s.Parent, s.Signature, s.Arity, s.ParameterTypes, s.ReturnType, semanticKey, s.Modifiers, conditionID); err != nil {
			return fmt.Errorf("insert class symbol: %w", err)
		}
	}

	for _, s := range result.Functions {
		name := cleanSymbolName(s.Name)
		if name == "" {
			continue
		}
		kind := "function"
		qn := name
		if s.Kind != "" {
			kind = s.Kind
		}
		if s.QualifiedName != "" {
			qn = s.QualifiedName
		}

		// Detect method vs function
		if s.Kind != "" {
			// Native extractors can classify the declaration directly.
		} else if s.Parent == "field_declaration_list" {
			// C++/C# inline method inside class body
			kind = "method"
			if s.Scope != "" {
				qn = s.Scope + "::" + name
			}
		} else if idx := findLastScopeOp(name); idx >= 0 {
			// C++ out-of-class method: Monster::takeDamage
			kind = "method"
			qn = name
			name = name[idx+2:] // just the method name
		} else if s.Scope != "" {
			// Has scope (class/struct/impl/interface) -> method
			// Go receiver, Python class method, Java/C# method, Rust impl method
			kind = "method"
			qn = s.Scope + "::" + name
		}

		semanticKey := s.SemanticKey
		if semanticKey == "" || kind != s.Kind || qn != s.QualifiedName {
			s.Kind, s.QualifiedName, s.Name = kind, qn, name
			semanticKey = semanticIdentity(lang, s)
		}
		conditionID, err := internCondition(tx, conditionCache, s.Condition)
		if err != nil {
			return err
		}
		if _, err := stmtSym.Exec(name, qn, kind, fileID, s.Line, s.EndLine, s.Col, s.Scope, s.Parent, s.Signature, s.Arity, s.ParameterTypes, s.ReturnType, semanticKey, s.Modifiers, conditionID); err != nil {
			return fmt.Errorf("insert symbol: %w", err)
		}
	}

	// Insert calls
	stmtCall, err := tx.Prepare(`INSERT INTO calls
		(caller_file_id, caller_line, callee_name, scope, caller_qualified_name,
		 callee_qualified_name, raw_text, receiver, resolution, confidence, arity,
		 argument_types, argument_expressions, receiver_type, condition_id, target_kind)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmtCall.Close()

	for _, s := range result.Calls {
		if s.Capture == "callee" && s.Name != "" {
			calleeQualified := s.QualifiedName
			if calleeQualified == "" {
				calleeQualified = s.Name
			}
			rawText := s.RawText
			if rawText == "" {
				rawText = calleeQualified
			}
			resolution := s.Resolution
			if resolution == "" {
				resolution = "unresolved"
			}
			confidence := s.Confidence
			if confidence <= 0 {
				if resolution == "exact" {
					confidence = 1
				} else {
					confidence = 0.20
				}
			}
			targetKind := s.TargetKind
			if targetKind == "" {
				targetKind = "unresolved"
				if resolution == "exact" {
					targetKind = "internal"
				}
			}
			conditionID, err := internCondition(tx, conditionCache, s.Condition)
			if err != nil {
				return err
			}
			if _, err := stmtCall.Exec(fileID, s.Line, s.Name, s.Scope, s.Scope, calleeQualified, rawText, s.Receiver, resolution, confidence, s.Arity, s.ArgumentTypes, s.ArgumentExpressions, s.ReceiverType, conditionID, targetKind); err != nil {
				return fmt.Errorf("insert call: %w", err)
			}
		}
	}

	if len(result.Variables) > 0 {
		stmtVar, err := tx.Prepare(`INSERT INTO variables
			(name, qualified_name, type_name, owner, kind, target, type_arguments, condition_id, file_id, line)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmtVar.Close()
		for _, variable := range result.Variables {
			if variable.Name == "" {
				continue
			}
			conditionID, err := internCondition(tx, conditionCache, variable.Condition)
			if err != nil {
				return err
			}
			if _, err := stmtVar.Exec(variable.Name, variable.QualifiedName, variable.TypeName, variable.Owner, variable.Kind, variable.Target, variable.TypeArguments, conditionID, fileID, variable.Line); err != nil {
				return fmt.Errorf("insert variable: %w", err)
			}
		}
	}

	if len(result.Macros) > 0 {
		stmtMacro, err := tx.Prepare(`INSERT INTO macros
			(name, qualified_name, body, function_like, arity, file_id, line, condition_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmtMacro.Close()
		for _, macro := range result.Macros {
			if macro.Name == "" {
				continue
			}
			conditionID, err := internCondition(tx, conditionCache, macro.Condition)
			if err != nil {
				return err
			}
			if _, err := stmtMacro.Exec(macro.Name, macro.QualifiedName, macro.Body, macro.FunctionLike, macro.Arity, fileID, macro.Line, conditionID); err != nil {
				return fmt.Errorf("insert macro: %w", err)
			}
		}
	}

	if len(result.Aliases) > 0 {
		stmtAlias, err := tx.Prepare(`INSERT INTO type_aliases
			(name, qualified_name, target, owner, kind, type_parameters, condition_id, file_id, line)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmtAlias.Close()
		for _, alias := range result.Aliases {
			if alias.Name == "" || alias.Target == "" {
				continue
			}
			conditionID, err := internCondition(tx, conditionCache, alias.Condition)
			if err != nil {
				return err
			}
			if _, err := stmtAlias.Exec(alias.Name, alias.QualifiedName, alias.Target, alias.Owner, alias.Kind, alias.TypeParameters, conditionID, fileID, alias.Line); err != nil {
				return fmt.Errorf("insert type alias: %w", err)
			}
		}
	}

	// Insert includes/imports
	if len(result.Imports) > 0 {
		stmtInc, err := tx.Prepare("INSERT INTO includes (file_id, included, line, condition_id) VALUES (?, ?, ?, ?)")
		if err != nil {
			return err
		}
		defer stmtInc.Close()
		for _, s := range result.Imports {
			if s.Name != "" {
				conditionID, err := internCondition(tx, conditionCache, s.Condition)
				if err != nil {
					return err
				}
				if _, err := stmtInc.Exec(fileID, s.Name, s.Line, conditionID); err != nil {
					return fmt.Errorf("insert include: %w", err)
				}
			}
		}
	}

	// Insert inheritance
	if len(result.Inheritance) > 0 {
		stmtInh, err := tx.Prepare("INSERT INTO inheritance (class_name, parent_name, file_id, line, relation_kind) VALUES (?, ?, ?, ?, ?)")
		if err != nil {
			return err
		}
		defer stmtInh.Close()
		for _, inh := range result.Inheritance {
			kind := inh.Kind
			if kind == "" {
				kind = "inherits"
			}
			if _, err := stmtInh.Exec(inh.ClassName, inh.ParentName, fileID, inh.Line, kind); err != nil {
				return fmt.Errorf("insert inheritance: %w", err)
			}
		}
	}

	return nil
}

// resolveSymbolKinds uses the complete project type set to distinguish
// out-of-class C++ method definitions from namespace-qualified free functions.
func resolveSymbolKinds(db *sql.DB) error {
	_, err := db.Exec(`UPDATE symbols AS candidate
		SET kind='method'
		WHERE candidate.kind='function' AND candidate.scope<>''
		  AND EXISTS (
		      SELECT 1 FROM symbols AS owner
		      WHERE owner.kind IN ('class','struct','interface','trait','record')
		        AND (owner.name=candidate.scope OR owner.qualified_name=candidate.scope
		             OR candidate.scope LIKE '%::' || owner.name)
		  )`)
	return err
}

// storeParseResultTxAtomic stores one file behind a savepoint so a failed file
// cannot leave partial deletes or inserts in a larger batch transaction.
func storeParseResultTxAtomic(tx *sql.Tx, savepoint string, filePath, lang string, result *ParseResult) error {
	hash, err := fileHash(filePath)
	if err != nil {
		return err
	}
	return storeParseResultTxAtomicHash(tx, savepoint, filePath, lang, hash, result)
}

func storeParseResultTxAtomicHash(tx *sql.Tx, savepoint string, filePath, lang, hash string, result *ParseResult) error {
	return storeParseResultTxAtomicHashWithConditionCache(tx, savepoint, filePath, lang, hash, result, make(map[string]any))
}

func storeParseResultTxAtomicHashWithConditionCache(tx *sql.Tx, savepoint string, filePath, lang, hash string, result *ParseResult, conditionCache map[string]any) error {
	return storeParseResultTxAtomicHashWithWorkspace(tx, savepoint, filePath, lang, hash, filepath.Dir(filePath), result, conditionCache)
}

func storeParseResultTxAtomicHashWithWorkspace(tx *sql.Tx, savepoint string, filePath, lang, hash, sourceRoot string, result *ParseResult, conditionCache map[string]any) error {
	if _, err := tx.Exec("SAVEPOINT " + savepoint); err != nil {
		return fmt.Errorf("create savepoint: %w", err)
	}
	if err := storeParseResultTxHashWithWorkspace(tx, filePath, lang, hash, sourceRoot, result, conditionCache); err != nil {
		rollbackErr := error(nil)
		if _, rbErr := tx.Exec("ROLLBACK TO " + savepoint); rbErr != nil {
			rollbackErr = rbErr
		}
		_, releaseErr := tx.Exec("RELEASE " + savepoint)
		if rollbackErr != nil {
			return fmt.Errorf("%w (rollback savepoint: %v)", err, rollbackErr)
		}
		if releaseErr != nil {
			return fmt.Errorf("%w (release savepoint: %v)", err, releaseErr)
		}
		return err
	}
	if _, err := tx.Exec("RELEASE " + savepoint); err != nil {
		return fmt.Errorf("release savepoint: %w", err)
	}
	return nil
}

// findLastScopeOp finds the last "::" in a name (for qualified names).
func findLastScopeOp(name string) int {
	for i := len(name) - 3; i >= 0; i-- {
		if name[i] == ':' && name[i+1] == ':' {
			return i
		}
	}
	return -1
}

// cleanSymbolName removes return type prefixes, parameter lists, and whitespace
// from raw symbol names extracted by tree-sitter.
// e.g. "* Dungeon::findMonster(const char* name)" -> "Dungeon::findMonster"
func cleanSymbolName(raw string) string {
	s := strings.TrimSpace(raw)
	// Remove parameter list: everything from first '('
	if idx := strings.Index(s, "("); idx >= 0 {
		s = strings.TrimSpace(s[:idx])
	}
	// Remove leading pointer/reference markers and type qualifiers
	for strings.HasPrefix(s, "*") || strings.HasPrefix(s, "&") {
		s = strings.TrimSpace(s[1:])
	}
	return s
}

// isFileChanged checks if a file needs re-indexing.
func isFileChanged(db *sql.DB, filePath string) (bool, error) {
	currentHash, err := fileHash(filePath)
	if err != nil {
		return true, err
	}

	var storedHash string
	err = db.QueryRow("SELECT hash FROM files WHERE path = ?", filePath).Scan(&storedHash)
	if err == sql.ErrNoRows {
		return true, nil // new file
	}
	if err != nil {
		return true, err
	}

	return currentHash != storedHash, nil
}
