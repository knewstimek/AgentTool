package codegraph

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRealWorldCodeGraph is an opt-in regression harness for large, external
// source trees. It is skipped in normal CI. Separate roots with | so Windows
// drive paths do not conflict with filepath.ListSeparator conventions.
func TestRealWorldCodeGraph(t *testing.T) {
	rawRoots := strings.TrimSpace(os.Getenv("CODEGRAPH_REALWORLD_ROOTS"))
	if rawRoots == "" {
		t.Skip("set CODEGRAPH_REALWORLD_ROOTS to opt into large-project indexing")
	}
	for _, root := range strings.Split(rawRoots, "|") {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		t.Run(filepath.Base(root), func(t *testing.T) {
			result, err := opIndex(CodeGraphInput{Path: root})
			if err != nil {
				t.Fatal(err)
			}
			t.Log(result)
			if os.Getenv("CODEGRAPH_RERESOLVE") == "1" {
				resolverDB, err := openDB(root)
				if err != nil {
					t.Fatal(err)
				}
				if err := resolveSymbolKinds(resolverDB); err != nil {
					resolverDB.Close()
					t.Fatal(err)
				}
				if err := resolveCallCandidates(resolverDB); err != nil {
					resolverDB.Close()
					t.Fatal(err)
				}
				resolverDB.Close()
			}
			stats, err := opStats(CodeGraphInput{Path: root})
			if err != nil {
				t.Fatal(err)
			}
			t.Log(stats)

			db, err := openDB(root)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			rows, err := db.Query(`SELECT callee_name, COUNT(*) AS uses
				FROM calls WHERE target_kind='unresolved'
				GROUP BY callee_name ORDER BY uses DESC, callee_name LIMIT 25`)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var top strings.Builder
			for rows.Next() {
				var name string
				var count int
				if err := rows.Scan(&name, &count); err != nil {
					t.Fatal(err)
				}
				fmt.Fprintf(&top, "%s=%d ", name, count)
			}
			t.Log("Top truly unresolved:", top.String())
			if debugName := strings.TrimSpace(os.Getenv("CODEGRAPH_DEBUG_NAME")); debugName != "" {
				debugRows, err := db.Query(`SELECT f.path, c.caller_line, c.raw_text, c.receiver, c.caller_qualified_name
					FROM calls c JOIN files f ON f.id=c.caller_file_id
					WHERE c.callee_name=? AND c.target_kind='unresolved' LIMIT 20`, debugName)
				if err != nil {
					t.Fatal(err)
				}
				defer debugRows.Close()
				for debugRows.Next() {
					var path, raw, receiver, caller string
					var line int
					if err := debugRows.Scan(&path, &line, &raw, &receiver, &caller); err != nil {
						t.Fatal(err)
					}
					t.Logf("unresolved %s:%d raw=%q receiver=%q caller=%q", path, line, raw, receiver, caller)
				}
				symbolRows, err := db.Query(`SELECT f.path, s.line, s.qualified_name, s.kind, s.arity
					FROM symbols s JOIN files f ON f.id=s.file_id WHERE s.name=? LIMIT 30`, debugName)
				if err != nil {
					t.Fatal(err)
				}
				defer symbolRows.Close()
				for symbolRows.Next() {
					var path, qualified, kind string
					var line, arity int
					if err := symbolRows.Scan(&path, &line, &qualified, &kind, &arity); err != nil {
						t.Fatal(err)
					}
					t.Logf("symbol %s:%d qn=%q kind=%q arity=%d", path, line, qualified, kind, arity)
				}
				variableRows, err := db.Query(`SELECT f.path,v.line,v.name,v.owner,v.kind,v.target,v.type_name
					FROM variables v JOIN files f ON f.id=v.file_id WHERE v.name=? LIMIT 30`, debugName)
				if err != nil {
					t.Fatal(err)
				}
				defer variableRows.Close()
				for variableRows.Next() {
					var path, name, owner, kind, target, typeName string
					var line int
					if err := variableRows.Scan(&path, &line, &name, &owner, &kind, &target, &typeName); err != nil {
						t.Fatal(err)
					}
					t.Logf("variable %s:%d name=%q owner=%q kind=%q target=%q type=%q", path, line, name, owner, kind, target, typeName)
				}
			}
			if info, err := os.Stat(filepath.Join(root, dbFileName)); err == nil {
				t.Logf("DB bytes: %d", info.Size())
			}
			var pageCount, freePages, pageSize, callbackFacts int
			_ = db.QueryRow("PRAGMA page_count").Scan(&pageCount)
			_ = db.QueryRow("PRAGMA freelist_count").Scan(&freePages)
			_ = db.QueryRow("PRAGMA page_size").Scan(&pageSize)
			_ = db.QueryRow("SELECT COUNT(*) FROM variables WHERE kind='callback'").Scan(&callbackFacts)
			t.Logf("DB pages: total=%d free=%d page_size=%d callback_facts=%d", pageCount, freePages, pageSize, callbackFacts)
			var conditionBytes, candidateTextBytes, callTextBytes int64
			_ = db.QueryRow(`SELECT COALESCE((SELECT SUM(length(expression)) FROM conditions),0)+COALESCE((SELECT SUM(length(condition)) FROM symbols),0)+COALESCE((SELECT SUM(length(condition)) FROM calls),0)+COALESCE((SELECT SUM(length(condition)) FROM variables),0)+COALESCE((SELECT SUM(length(condition)) FROM includes),0)+COALESCE((SELECT SUM(length(condition)) FROM macros),0)`).Scan(&conditionBytes)
			_ = db.QueryRow("SELECT COALESCE(SUM(length(basis)+length(evidence)),0) FROM call_candidates").Scan(&candidateTextBytes)
			_ = db.QueryRow("SELECT COALESCE(SUM(length(raw_text)+length(argument_types)+length(argument_expressions)),0) FROM calls").Scan(&callTextBytes)
			t.Logf("DB text bytes: conditions=%d candidates=%d calls=%d", conditionBytes, candidateTextBytes, callTextBytes)
		})
	}
}

func TestRealWorldWorkspaceCodeGraph(t *testing.T) {
	dbRoot := strings.TrimSpace(os.Getenv("CODEGRAPH_REALWORLD_WORKSPACE_DB"))
	rawRoots := strings.TrimSpace(os.Getenv("CODEGRAPH_REALWORLD_WORKSPACE_ROOTS"))
	if dbRoot == "" || rawRoots == "" {
		t.Skip("set CODEGRAPH_REALWORLD_WORKSPACE_DB and CODEGRAPH_REALWORLD_WORKSPACE_ROOTS")
	}
	var roots []string
	for _, root := range strings.Split(rawRoots, "|") {
		if root = strings.TrimSpace(root); root != "" {
			roots = append(roots, root)
		}
	}
	result, err := opIndex(CodeGraphInput{Path: dbRoot, Roots: roots})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)
	if os.Getenv("CODEGRAPH_RERESOLVE") == "1" {
		db, err := openDB(dbRoot)
		if err != nil {
			t.Fatal(err)
		}
		if err := resolveSymbolKinds(db); err != nil {
			db.Close()
			t.Fatal(err)
		}
		if err := resolveCallCandidates(db); err != nil {
			db.Close()
			t.Fatal(err)
		}
		db.Close()
	}
	stats, err := opStats(CodeGraphInput{Path: dbRoot})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(stats)
	if info, err := os.Stat(filepath.Join(dbRoot, dbFileName)); err == nil {
		t.Logf("Workspace DB bytes: %d", info.Size())
	}
	if reportRoots := strings.TrimSpace(os.Getenv("CODEGRAPH_REALWORLD_REPORT_ROOTS")); reportRoots != "" {
		db, err := openDB(dbRoot)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		for _, reportRoot := range strings.Split(reportRoots, "|") {
			reportRoot = strings.TrimSpace(reportRoot)
			if reportRoot == "" {
				continue
			}
			var calls, exact, candidate, external, macros, callbacks, unresolved int
			pattern := filepath.Clean(reportRoot) + string(os.PathSeparator) + "%"
			err := db.QueryRow(`SELECT COUNT(*),
				SUM(c.target_kind='internal' AND c.resolution='exact'),
				SUM(c.target_kind='internal' AND c.resolution<>'exact'),
				SUM(c.target_kind='external'),SUM(c.target_kind='macro'),
				SUM(c.target_kind='callback'),SUM(c.target_kind='unresolved')
				FROM calls c JOIN files f ON f.id=c.caller_file_id WHERE f.path LIKE ?`, pattern).Scan(
				&calls, &exact, &candidate, &external, &macros, &callbacks, &unresolved)
			if err != nil {
				t.Fatal(err)
			}
			rate := 0.0
			if calls > 0 {
				rate = float64(unresolved) * 100 / float64(calls)
			}
			t.Logf("Root %s: calls=%d exact=%d candidate=%d external=%d macro=%d callback=%d unresolved=%d (%.2f%%)", reportRoot, calls, exact, candidate, external, macros, callbacks, unresolved, rate)
		}
	}
}
