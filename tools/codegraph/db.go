package codegraph

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const dbFileName = ".codegraph.db"

const schemaSQL = `
CREATE TABLE IF NOT EXISTS files (
	id INTEGER PRIMARY KEY,
	path TEXT NOT NULL UNIQUE,
	hash TEXT NOT NULL,
	language TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS symbols (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	qualified_name TEXT NOT NULL,
	kind TEXT NOT NULL,
	file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
	line INTEGER NOT NULL,
	col INTEGER NOT NULL,
	scope TEXT NOT NULL DEFAULT '',
	parent_kind TEXT NOT NULL DEFAULT '',
	UNIQUE(qualified_name, file_id, line)
);

CREATE TABLE IF NOT EXISTS calls (
	id INTEGER PRIMARY KEY,
	caller_file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
	caller_line INTEGER NOT NULL,
	callee_name TEXT NOT NULL,
	scope TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_symbols_qn ON symbols(qualified_name);
CREATE INDEX IF NOT EXISTS idx_symbols_kind ON symbols(kind);
CREATE INDEX IF NOT EXISTS idx_symbols_file ON symbols(file_id);
CREATE INDEX IF NOT EXISTS idx_calls_callee ON calls(callee_name);
CREATE INDEX IF NOT EXISTS idx_calls_file ON calls(caller_file_id);
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

	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	return db, nil
}

// fileHash returns a simple hash of file metadata for change detection.
func fileHash(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d_%d", fi.Size(), fi.ModTime().UnixNano()), nil
}

// storeParseResult saves parsed symbols and calls to the database.
func storeParseResult(db *sql.DB, filePath, lang string, result *ParseResult) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	hash, err := fileHash(filePath)
	if err != nil {
		return err
	}

	// Upsert file
	var fileID int64
	row := tx.QueryRow("SELECT id FROM files WHERE path = ?", filePath)
	if err := row.Scan(&fileID); err == sql.ErrNoRows {
		res, err := tx.Exec("INSERT INTO files (path, hash, language) VALUES (?, ?, ?)", filePath, hash, lang)
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
		if _, err := tx.Exec("DELETE FROM calls WHERE file_id = ?", fileID); err != nil {
			return fmt.Errorf("delete old calls: %w", err)
		}
		if _, err := tx.Exec("UPDATE files SET hash = ?, language = ? WHERE id = ?", hash, lang, fileID); err != nil {
			return fmt.Errorf("update file hash: %w", err)
		}
	}

	// Insert symbols
	stmtSym, err := tx.Prepare("INSERT OR IGNORE INTO symbols (name, qualified_name, kind, file_id, line, col, scope, parent_kind) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmtSym.Close()

	for _, s := range result.Classes {
		qn := s.Name
		if s.Scope != "" {
			qn = s.Scope + "::" + s.Name
		}
		stmtSym.Exec(s.Name, qn, "class", fileID, s.Line, s.Col, s.Scope, s.Parent)
	}

	for _, s := range result.Functions {
		name := cleanSymbolName(s.Name)
		if name == "" {
			continue
		}
		kind := "function"
		qn := name

		// Detect method vs function
		if s.Parent == "field_declaration_list" {
			kind = "method"
			if s.Scope != "" {
				qn = s.Scope + "::" + name
			}
		} else if idx := findLastScopeOp(name); idx >= 0 {
			// Out-of-class method: Monster::takeDamage
			kind = "method"
			qn = name
			name = name[idx+2:] // just the method name
		} else if s.Scope != "" {
			qn = s.Scope + "::" + name
		}

		stmtSym.Exec(name, qn, kind, fileID, s.Line, s.Col, s.Scope, s.Parent)
	}

	// Insert calls
	stmtCall, err := tx.Prepare("INSERT INTO calls (caller_file_id, caller_line, callee_name, scope) VALUES (?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmtCall.Close()

	for _, s := range result.Calls {
		if s.Capture == "callee" && s.Name != "" {
			stmtCall.Exec(fileID, s.Line, s.Name, s.Scope)
		}
	}

	return tx.Commit()
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
