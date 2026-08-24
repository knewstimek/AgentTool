package codegraph

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenDBMigratesLegacySchema(t *testing.T) {
	root := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(root, dbFileName))
	if err != nil {
		t.Fatal(err)
	}
	legacySchema := `
CREATE TABLE files (id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE, hash TEXT NOT NULL, language TEXT NOT NULL);
CREATE TABLE symbols (id INTEGER PRIMARY KEY, name TEXT NOT NULL, qualified_name TEXT NOT NULL, kind TEXT NOT NULL, file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE, line INTEGER NOT NULL, col INTEGER NOT NULL, scope TEXT NOT NULL DEFAULT '', parent_kind TEXT NOT NULL DEFAULT '', UNIQUE(qualified_name, file_id, line));
CREATE TABLE calls (id INTEGER PRIMARY KEY, caller_file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE, caller_line INTEGER NOT NULL, callee_name TEXT NOT NULL, scope TEXT NOT NULL DEFAULT '');
CREATE TABLE inheritance (id INTEGER PRIMARY KEY, class_name TEXT NOT NULL, parent_name TEXT NOT NULL, file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE, line INTEGER NOT NULL);
CREATE TABLE includes (id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE, included TEXT NOT NULL, line INTEGER NOT NULL);`
	if _, err := legacy.Exec(legacySchema); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := openDB(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for table, columns := range map[string][]string{
		"files":       {"source_root"},
		"symbols":     {"end_line", "signature", "arity", "parameter_types", "return_type", "semantic_key", "modifiers", "condition", "condition_id"},
		"calls":       {"caller_qualified_name", "callee_qualified_name", "raw_text", "receiver", "resolution", "confidence", "arity", "argument_types", "argument_expressions", "receiver_type", "condition", "condition_id", "target_kind"},
		"inheritance": {"relation_kind"},
		"includes":    {"resolved_file_id", "condition"},
	} {
		for _, column := range columns {
			exists, err := tableHasColumn(db, table, column)
			if err != nil || !exists {
				t.Fatalf("expected migrated column %s.%s (exists=%v, err=%v)", table, column, exists, err)
			}
		}
	}
	var version string
	if err := db.QueryRow("SELECT value FROM codegraph_meta WHERE key='schema_version'").Scan(&version); err != nil || version != "4" {
		t.Fatalf("schema version = %q, err=%v", version, err)
	}
}

func TestProjectResolverClassifiesCPPReceiverChainsAndNonRuntimeCalls(t *testing.T) {
	root := t.TempDir()
	header := `
class CSpriteSurface {
public:
    void Unlock();
};
class Base {
public:
    CSpriteSurface * m_p_DDSurface_back;
    void Paint();
};
extern Base * gpC_base;
#define RGB(r,g,b) ((r) | (g) | (b))
`
	source := `
#include "types.h"
#include <cstring>
void helper() {}
void CSpriteSurface::Unlock() {}
void Base::Paint() {
    gpC_base->m_p_DDSurface_back->Unlock();
    auto baseAlias = gpC_base;
    auto surfaceAlias = baseAlias->m_p_DDSurface_back;
    surfaceAlias->Unlock();
    RGB(1, 2, 3);
    memcpy(0, 0, 0);
    std::vector<int> values;
    values.clear();
    GetPrivateProfileInt("a", "b", 0, "c");
    void (*callback)() = helper;
    callback();
    auto local = [](int value) { helper(); };
    local(1);
}
`
	if err := os.WriteFile(filepath.Join(root, "types.h"), []byte(header), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "paint.cpp"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := opIndex(CodeGraphInput{Path: root, Workers: 1}); err != nil {
		t.Fatal(err)
	}
	db, err := openDB(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	assertCallClass := func(name, targetKind, resolution, qualified string) {
		t.Helper()
		var gotKind, gotResolution, gotQualified string
		if err := db.QueryRow("SELECT target_kind, resolution, callee_qualified_name FROM calls WHERE callee_name=? LIMIT 1", name).Scan(&gotKind, &gotResolution, &gotQualified); err != nil {
			t.Fatalf("query %s: %v", name, err)
		}
		if gotKind != targetKind || gotResolution != resolution || qualified != "" && gotQualified != qualified {
			t.Fatalf("%s = kind %q resolution %q qualified %q, want %q %q %q", name, gotKind, gotResolution, gotQualified, targetKind, resolution, qualified)
		}
	}
	assertCallClass("Unlock", "internal", "exact", "CSpriteSurface::Unlock")
	var unlocks int
	if err := db.QueryRow("SELECT COUNT(*) FROM calls WHERE callee_name='Unlock' AND callee_qualified_name='CSpriteSurface::Unlock' AND resolution='exact'").Scan(&unlocks); err != nil || unlocks != 2 {
		t.Fatalf("fixed-point alias Unlock count=%d err=%v", unlocks, err)
	}
	assertCallClass("RGB", "macro", "classified", "RGB")
	assertCallClass("memcpy", "external", "classified", "")
	assertCallClass("clear", "external", "classified", "std::vector::clear")
	assertCallClass("GetPrivateProfileInt", "external", "classified", "")
	assertCallClass("callback", "callback", "exact", "helper")
	assertCallClass("local", "callback", "exact", "")
	for table, want := range map[string]int{"macro_uses": 1, "callback_edges": 2} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != want {
			t.Fatalf("%s count=%d want=%d err=%v", table, count, want, err)
		}
	}
	stats, err := opStats(CodeGraphInput{Path: root})
	if err != nil || !strings.Contains(stats, "Truly unresolved: 0 (0.00%)") {
		rows, _ := db.Query("SELECT callee_name, raw_text, target_kind, resolution FROM calls ORDER BY caller_line")
		var details strings.Builder
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var name, raw, kind, resolution string
				_ = rows.Scan(&name, &raw, &kind, &resolution)
				details.WriteString(name + ":" + raw + ":" + kind + ":" + resolution + "; ")
			}
		}
		t.Fatalf("classification stats = %q, calls=%s err=%v", stats, details.String(), err)
	}
}

func TestProjectResolverPropagatesGenericBoundsAcrossRustCSharpAndJava(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"generic.rs": `
trait Runner { fn run(&self); fn make(); }
fn execute<T: Runner>(value: T) { value.run(); T::make(); }
fn helper() {}
fn callbacks() {
    let callback = || helper();
    callback();
}
`,
		"Generic.cs": `
namespace Demo;
interface Worker { void Run(); }
class Use {
    void Execute<T>(T value) where T : Worker { value.Run(); }
    void Helper() {}
    void Callbacks() { var callback = () => Helper(); callback(); }
}
`,
		"Generic.java": `
package sample;
interface Worker { void run(); }
class Use {
    <T extends Worker> void execute(T value) { value.run(); }
    void helper() {}
    void callbacks() { Runnable callback = () -> { helper(); }; callback.run(); }
}
`,
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if result, err := opIndex(CodeGraphInput{Path: root, Workers: 1}); err != nil || !strings.Contains(result, "0 errors") {
		t.Fatalf("index = %q, err=%v", result, err)
	}
	db, err := openDB(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, qualified := range []string{"Runner::run", "Runner::make", "Demo::Worker::Run", "sample::Worker::run"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM calls WHERE callee_qualified_name=? AND target_kind='internal' AND resolution='exact'", qualified).Scan(&count); err != nil || count != 1 {
			t.Fatalf("generic target %s count=%d err=%v", qualified, count, err)
		}
	}
	var callbacks int
	if err := db.QueryRow("SELECT COUNT(*) FROM calls WHERE target_kind='callback'").Scan(&callbacks); err != nil || callbacks != 3 {
		t.Fatalf("cross-language callback count=%d err=%v", callbacks, err)
	}
}

func TestProjectResolverRanksOverloadsByArityAndLiteralType(t *testing.T) {
	root := t.TempDir()
	source := `
void choose(int value) {}
void choose(const char * value) {}
void choose(int left, int right) {}
void use() { choose(1); choose("text"); choose(1, 2); }
`
	if err := os.WriteFile(filepath.Join(root, "overload.cpp"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := opIndex(CodeGraphInput{Path: root, Workers: 1}); err != nil {
		t.Fatal(err)
	}
	db, err := openDB(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT c.caller_line, s.signature, cc.confidence
		FROM calls c JOIN call_candidates cc ON cc.call_id=c.id JOIN symbols s ON s.id=cc.symbol_id
		WHERE c.callee_name='choose'
		  AND cc.confidence=(SELECT MAX(best.confidence) FROM call_candidates best WHERE best.call_id=c.id)
		ORDER BY c.caller_line, c.id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var signatures []string
	for rows.Next() {
		var line int
		var signature string
		var confidence float64
		if err := rows.Scan(&line, &signature, &confidence); err != nil {
			t.Fatal(err)
		}
		signatures = append(signatures, signature)
	}
	joined := strings.Join(signatures, "\n")
	for _, expected := range []string{"choose(int value)", "choose(const char * value)", "choose(int left, int right)"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("overload %q was not top-ranked; got %q", expected, joined)
		}
	}
}

func TestSemanticEvidenceCalibrationIsMonotonicAndDeterministic(t *testing.T) {
	call := semanticCall{name: "run", qualified: "run", arity: 1, argumentTypes: "int", path: filepath.Join("workspace", "src", "caller.cpp"), fileID: 1}
	symbol := semanticSymbol{name: "run", qualified: "library::run", kind: "function", arity: 1,
		parameterTypes: "int", signature: "void run(int value)", language: "cpp",
		path: filepath.Join("workspace", "include", "library.h"), fileID: 2}
	parents := map[string][]string{}
	baseline, baselineEvidence := semanticCandidateScore(call, "", symbol, nil, 2, parents)
	withInclude, includeEvidence := semanticCandidateScore(call, "", symbol, []string{"library.h"}, 2, parents)
	mismatch := symbol
	mismatch.arity = 2
	withMismatch, _ := semanticCandidateScore(call, "", mismatch, []string{"library.h"}, 2, parents)
	repeated, repeatedEvidence := semanticCandidateScore(call, "", symbol, []string{"library.h"}, 2, parents)
	if !(withInclude > baseline && withInclude > withMismatch) {
		t.Fatalf("non-monotonic evidence baseline=%f include=%f mismatch=%f", baseline, withInclude, withMismatch)
	}
	if repeated != withInclude || strings.Join(repeatedEvidence, "+") != strings.Join(includeEvidence, "+") {
		t.Fatalf("non-deterministic score first=%f/%v repeated=%f/%v baselineEvidence=%v", withInclude, includeEvidence, repeated, repeatedEvidence, baselineEvidence)
	}
	for _, value := range []float64{-4, -1, 0, 1, 4} {
		if calibratedProbability(value) <= 0 || calibratedProbability(value) >= 1 {
			t.Fatalf("uncalibrated probability(%f)=%f", value, calibratedProbability(value))
		}
	}
}

func TestParallelIndexProducesDeterministicSemanticResolution(t *testing.T) {
	indexCopy := func(workers int) string {
		root := t.TempDir()
		for index := 0; index < 24; index++ {
			directory := filepath.Join(root, "module"+itoa(index))
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			source := "namespace module" + itoa(index) + " { void choose(int value) {} void choose(const char* value) {} }\n"
			if err := os.WriteFile(filepath.Join(directory, "api.cpp"), []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		caller := "namespace module7 { void use() { choose(1); choose(\"x\"); } }\n"
		if err := os.WriteFile(filepath.Join(root, "caller.cpp"), []byte(caller), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := opIndex(CodeGraphInput{Path: root, Workers: workers}); err != nil {
			t.Fatal(err)
		}
		db, err := openDB(root)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		rows, err := db.Query(`SELECT c.raw_text,c.caller_line,c.callee_qualified_name,c.resolution,
			printf('%.12f',c.confidence),COALESCE(ss.semantic_key,''),COALESCE(cc.basis,'')
			FROM calls c LEFT JOIN call_candidates cc ON cc.call_id=c.id
			LEFT JOIN semantic_symbols ss ON ss.id=cc.semantic_id
			ORDER BY c.caller_line,c.raw_text,cc.confidence DESC,ss.semantic_key`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var snapshot strings.Builder
		for rows.Next() {
			var raw, qualified, resolution, confidence, semanticKey, basis string
			var line int
			if err := rows.Scan(&raw, &line, &qualified, &resolution, &confidence, &semanticKey, &basis); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&snapshot, "%d|%s|%s|%s|%s|%s|%s\n", line, raw, qualified, resolution, confidence, semanticKey, basis)
		}
		return snapshot.String()
	}
	serial := indexCopy(1)
	parallel := indexCopy(4)
	if serial != parallel {
		t.Fatalf("parallel semantic graph differs\nserial:\n%s\nparallel:\n%s", serial, parallel)
	}
}

func TestProjectResolverHandlesGoFieldChainsGenericsAndFunctionValues(t *testing.T) {
	root := t.TempDir()
	source := `package sample
type Runner interface { Run() }
type Leaf struct{}
func (l *Leaf) Run() {}
type Root struct { Child *Leaf }
var Global *Root
func generic[T Runner](value T) { value.Run() }
func callbacks() {
    callback := generic[Runner]
    callback(nil)
    closure := func() { Global.Child.Run() }
    closure()
}
`
	if err := os.WriteFile(filepath.Join(root, "semantic.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := opIndex(CodeGraphInput{Path: root, Workers: 1}); err != nil {
		t.Fatal(err)
	}
	db, err := openDB(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var fieldChain int
	if err := db.QueryRow("SELECT COUNT(*) FROM calls WHERE raw_text='Global.Child.Run' AND callee_qualified_name='sample::Leaf::Run' AND resolution='exact'").Scan(&fieldChain); err != nil || fieldChain != 1 {
		t.Fatalf("Go field chain count=%d err=%v", fieldChain, err)
	}
	var callbacks int
	if err := db.QueryRow("SELECT COUNT(*) FROM calls WHERE callee_name IN ('callback','closure') AND target_kind='callback' AND resolution='exact'").Scan(&callbacks); err != nil || callbacks != 2 {
		t.Fatalf("Go callback count=%d err=%v", callbacks, err)
	}
	var generic int
	if err := db.QueryRow("SELECT COUNT(*) FROM calls WHERE raw_text='value.Run' AND callee_qualified_name='sample::Runner::Run' AND resolution='exact'").Scan(&generic); err != nil || generic != 1 {
		t.Fatalf("Go generic receiver count=%d err=%v", generic, err)
	}
	var dispatch int
	if err := db.QueryRow(`SELECT COUNT(*) FROM dispatch_edges d JOIN calls c ON c.id=d.call_id
		WHERE c.raw_text='value.Run'`).Scan(&dispatch); err != nil || dispatch != 1 {
		t.Fatalf("Go interface implementation dispatch count=%d err=%v", dispatch, err)
	}
}

func TestOverloadDataFlowUsesVariablesAndReturnValues(t *testing.T) {
	root := t.TempDir()
	source := `
class Thing {};
Thing makeThing();
void select(Thing value) {}
void select(int value) {}
Thing makeThing() { return Thing(); }
void use() {
    Thing value;
    select(value);
    select(makeThing());
}
`
	if err := os.WriteFile(filepath.Join(root, "flow.cpp"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := opIndex(CodeGraphInput{Path: root, Workers: 1}); err != nil {
		t.Fatal(err)
	}
	db, err := openDB(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT c.argument_types,s.parameter_types,cc.basis
		FROM calls c JOIN call_candidates cc ON cc.call_id=c.id
		JOIN symbols s ON s.id=cc.symbol_id
		WHERE c.callee_name='select'
		  AND cc.confidence=(SELECT MAX(best.confidence) FROM call_candidates best WHERE best.call_id=c.id)
		ORDER BY c.caller_line,c.id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var argumentTypes, parameterTypes, basis string
		if err := rows.Scan(&argumentTypes, &parameterTypes, &basis); err != nil {
			t.Fatal(err)
		}
		if argumentTypes != "Thing" || parameterTypes != "Thing" || !strings.Contains(basis, "argument-types") {
			t.Fatalf("data-flow overload argument=%q parameter=%q basis=%q", argumentTypes, parameterTypes, basis)
		}
		count++
	}
	if count != 2 {
		t.Fatalf("data-flow overload count=%d", count)
	}
}

func TestProjectResolverUsesIncludeAndDirectoryProximity(t *testing.T) {
	root := t.TempDir()
	paths := map[string]string{
		filepath.Join("src", "preferred.h"): "namespace preferred { void run(); }\n",
		filepath.Join("lib", "fallback.h"):  "namespace fallback { void run(); }\n",
		filepath.Join("src", "caller.cpp"):  "#include \"preferred.h\"\nvoid use() { run(); }\n",
	}
	for relative, source := range paths {
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := opIndex(CodeGraphInput{Path: root, Workers: 1}); err != nil {
		t.Fatal(err)
	}
	db, err := openDB(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var qualified, resolution, basis string
	if err := db.QueryRow(`SELECT c.callee_qualified_name, c.resolution, cc.basis
		FROM calls c JOIN call_candidates cc ON cc.call_id=c.id
		JOIN symbols s ON s.id=cc.symbol_id
		WHERE c.callee_name='run' ORDER BY cc.confidence DESC LIMIT 1`).Scan(&qualified, &resolution, &basis); err != nil {
		t.Fatal(err)
	}
	if qualified != "preferred::run" || resolution != "exact" || !strings.Contains(basis, "include") || !strings.Contains(basis, "path") {
		t.Fatalf("include/path ranking = qualified %q resolution %q basis %q", qualified, resolution, basis)
	}
}

func TestExtractorVersionForcesStructuralRefresh(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "sample.go")
	if err := os.WriteFile(file, []byte("package sample\nfunc old() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := openDB(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := storeParseResult(db, file, "go", &ParseResult{Functions: []Symbol{{Name: "old", Line: 2, EndLine: 2}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO codegraph_meta(key,value) VALUES('extractor_version','old')
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err != nil {
		t.Fatal(err)
	}
	refreshed, err := prepareExtractorVersion(db)
	if err != nil || !refreshed {
		t.Fatalf("expected extractor refresh, refreshed=%v err=%v", refreshed, err)
	}
	var hash string
	if err := db.QueryRow("SELECT hash FROM files WHERE path=?", file).Scan(&hash); err != nil || hash != "" {
		t.Fatalf("file hash was not invalidated: %q err=%v", hash, err)
	}
	refreshed, err = prepareExtractorVersion(db)
	if err != nil || refreshed {
		t.Fatalf("current extractor version refreshed twice, refreshed=%v err=%v", refreshed, err)
	}
}

func TestSemanticV4ReturnChainsIdentityConditionsIncludesAndDispatch(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"api.h": `
class Product {
public:
    virtual int Value(int x);
};
class Factory {
public:
    Product* Make();
};
using ProductPtr = std::unique_ptr<Product>;
ProductPtr Smart();
class Base {
public:
    virtual void Execute();
};
class Derived : public Base {
public:
    void Execute() override;
};
#if FEATURE_X
void ConditionalFeature();
#endif
`,
		"middle.h": `#include "api.h"`,
		"impl.cpp": `
#include "middle.h"
int Product::Value(int x) { return x; }
Product* Factory::Make() { return nullptr; }
ProductPtr Smart() { return ProductPtr(); }
void Base::Execute() {}
void Derived::Execute() {}
void Use(Factory* factory, Base* base) {
    factory->Make()->Value(1);
    Smart()->Value(2);
    base->Execute();
}
`,
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := opIndex(CodeGraphInput{Path: root, Workers: 1}); err != nil {
		t.Fatal(err)
	}
	db, err := openDB(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var semanticCount, occurrenceCount int
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(SUM((SELECT COUNT(*) FROM symbol_occurrences so WHERE so.semantic_id=ss.id)),0)
		FROM semantic_symbols ss WHERE ss.qualified_name='Factory::Make'`).Scan(&semanticCount, &occurrenceCount); err != nil {
		t.Fatal(err)
	}
	if semanticCount != 1 || occurrenceCount != 2 {
		rows, _ := db.Query("SELECT qualified_name,kind,return_type,parameter_types FROM semantic_symbols ORDER BY qualified_name")
		for rows != nil && rows.Next() {
			var q, k, r, p string
			_ = rows.Scan(&q, &k, &r, &p)
			t.Logf("semantic %q %q return=%q params=%q", q, k, r, p)
		}
		if rows != nil {
			rows.Close()
		}
		t.Fatalf("Factory::Make semantic=%d occurrences=%d", semanticCount, occurrenceCount)
	}
	for _, call := range []struct{ raw, receiver string }{{"factory->Make()->Value", "Product"}, {"Smart()->Value", "Product"}} {
		var receiver, qualified, resolution string
		if err := db.QueryRow("SELECT receiver_type,callee_qualified_name,resolution FROM calls WHERE raw_text=?", call.raw).Scan(&receiver, &qualified, &resolution); err != nil {
			rows, _ := db.Query("SELECT callee_name,raw_text,receiver,receiver_type,callee_qualified_name,resolution FROM calls ORDER BY caller_line")
			for rows != nil && rows.Next() {
				var name, raw, receiverExpression, receiverType, target, state string
				_ = rows.Scan(&name, &raw, &receiverExpression, &receiverType, &target, &state)
				t.Logf("call name=%q raw=%q receiver=%q type=%q target=%q state=%q", name, raw, receiverExpression, receiverType, target, state)
			}
			if rows != nil {
				rows.Close()
			}
			t.Fatalf("query %s: %v", call.raw, err)
		}
		if receiver != call.receiver || qualified != "Product::Value" || resolution != "exact" {
			rows, _ := db.Query(`SELECT cc.confidence,cc.basis,s.qualified_name FROM calls c JOIN call_candidates cc ON cc.call_id=c.id JOIN symbols s ON s.id=cc.symbol_id WHERE c.raw_text=?`, call.raw)
			for rows != nil && rows.Next() {
				var score float64
				var basis, target string
				_ = rows.Scan(&score, &basis, &target)
				t.Logf("candidate %s %.6f %s", target, score, basis)
			}
			if rows != nil {
				rows.Close()
			}
			t.Fatalf("%s receiver=%q qualified=%q resolution=%q", call.raw, receiver, qualified, resolution)
		}
	}
	var transitiveDistance int
	if err := db.QueryRow(`SELECT e.distance FROM include_edges e
		JOIN files source ON source.id=e.file_id JOIN files target ON target.id=e.included_file_id
		WHERE source.path LIKE '%impl.cpp' AND target.path LIKE '%api.h'`).Scan(&transitiveDistance); err != nil || transitiveDistance != 2 {
		t.Fatalf("transitive include distance=%d err=%v", transitiveDistance, err)
	}
	var condition string
	if err := db.QueryRow("SELECT COALESCE(c.expression,s.condition) FROM symbols s LEFT JOIN conditions c ON c.id=s.condition_id WHERE s.name='ConditionalFeature'").Scan(&condition); err != nil || !strings.Contains(condition, "FEATURE_X") {
		t.Fatalf("condition=%q err=%v", condition, err)
	}
	var dispatchCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM dispatch_edges d JOIN calls c ON c.id=d.call_id
		WHERE c.raw_text='base->Execute'`).Scan(&dispatchCount); err != nil || dispatchCount != 1 {
		t.Fatalf("dispatch targets=%d err=%v", dispatchCount, err)
	}
}

func TestMultiRootWorkspaceResolvesAcrossProjects(t *testing.T) {
	workspace := t.TempDir()
	first := filepath.Join(workspace, "library")
	second := filepath.Join(workspace, "application")
	if err := os.MkdirAll(first, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(second, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(first, "service.h"), []byte("class Service {\npublic:\n    void Run();\n};\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(second, "main.cpp"), []byte("#include \"../library/service.h\"\nvoid Use(Service* service) { service->Run(); }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := opIndex(CodeGraphInput{Path: workspace, Roots: []string{first, second}, Workers: 1}); err != nil {
		t.Fatal(err)
	}
	db, err := openDB(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var files, exact int
	if err := db.QueryRow("SELECT COUNT(*) FROM files").Scan(&files); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM calls WHERE callee_name='Run' AND callee_qualified_name='Service::Run' AND resolution='exact'").Scan(&exact); err != nil {
		t.Fatal(err)
	}
	if files != 2 || exact != 1 {
		rows, _ := db.Query("SELECT raw_text,receiver,receiver_type,callee_qualified_name,resolution,confidence FROM calls")
		for rows != nil && rows.Next() {
			var raw, receiver, receiverType, qualified, resolution string
			var confidence float64
			_ = rows.Scan(&raw, &receiver, &receiverType, &qualified, &resolution, &confidence)
			t.Logf("call raw=%q receiver=%q type=%q qualified=%q resolution=%q confidence=%f", raw, receiver, receiverType, qualified, resolution, confidence)
		}
		if rows != nil {
			rows.Close()
		}
		t.Fatalf("workspace files=%d exact=%d", files, exact)
	}
}

func TestAdvancedLanguageRelationsResolveWithoutToolchains(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"extension.cs": `
class Service {}
static class ServiceExtensions {
    public static void Ping(this Service service) {}
}
class Consumer {
    void Use(Service service) { service.Ping(); }
}
`,
		"semantic.rs": `
use std::ops::Deref;
macro_rules! local_macro { () => {} }
struct Product;
impl Product { fn work(&self) {} }
struct Wrapped(Product);
impl Deref for Wrapped {
    type Target = Product;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl Wrapped { fn item(&self) -> &Self::Target { &self.0 } }
fn consume(value: Wrapped) { value.work(); value.item().work(); local_macro!(); }
`,
		"Reference.java": `
class Reference {
    void target() {}
    void use() { Runnable callback = this::target; callback.run(); }
}
`,
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := opIndex(CodeGraphInput{Path: root, Workers: 1}); err != nil {
		t.Fatal(err)
	}
	db, err := openDB(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	assertCount := func(query string, expected int, label string) {
		t.Helper()
		var count int
		if err := db.QueryRow(query).Scan(&count); err != nil || count != expected {
			rows, _ := db.Query("SELECT raw_text,receiver,receiver_type,callee_qualified_name,resolution,target_kind FROM calls ORDER BY caller_file_id,caller_line")
			for rows != nil && rows.Next() {
				var raw, receiver, receiverType, target, resolution, kind string
				_ = rows.Scan(&raw, &receiver, &receiverType, &target, &resolution, &kind)
				t.Logf("call raw=%q receiver=%q type=%q target=%q resolution=%q kind=%q", raw, receiver, receiverType, target, resolution, kind)
			}
			if rows != nil {
				rows.Close()
			}
			aliasRows, _ := db.Query("SELECT name,target,owner,qualified_name FROM type_aliases")
			for aliasRows != nil && aliasRows.Next() {
				var name, target, owner, qualified string
				_ = aliasRows.Scan(&name, &target, &owner, &qualified)
				t.Logf("alias %q -> %q owner=%q qualified=%q", name, target, owner, qualified)
			}
			if aliasRows != nil {
				aliasRows.Close()
			}
			relationRows, _ := db.Query("SELECT class_name,parent_name,relation_kind FROM inheritance")
			for relationRows != nil && relationRows.Next() {
				var child, parent, kind string
				_ = relationRows.Scan(&child, &parent, &kind)
				t.Logf("relation %q -> %q kind=%q", child, parent, kind)
			}
			if relationRows != nil {
				relationRows.Close()
			}
			t.Fatalf("%s count=%d err=%v", label, count, err)
		}
	}
	assertCount("SELECT COUNT(*) FROM calls WHERE raw_text='service.Ping' AND callee_qualified_name='ServiceExtensions::Ping' AND resolution='exact'", 1, "C# extension")
	assertCount("SELECT COUNT(*) FROM calls WHERE raw_text='value.work' AND callee_qualified_name='Product::work' AND resolution='exact'", 1, "Rust Deref")
	assertCount("SELECT COUNT(*) FROM calls WHERE raw_text='value.item().work' AND receiver_type='Product' AND callee_qualified_name='Product::work' AND resolution='exact'", 1, "Rust associated return")
	assertCount("SELECT COUNT(*) FROM calls WHERE callee_name='local_macro' AND target_kind='macro'", 1, "Rust macro")
	assertCount("SELECT COUNT(*) FROM calls WHERE raw_text='callback.run' AND target_kind='callback'", 1, "Java method reference")
}

func TestResolveSymbolKindsUsesTypesFromOtherFiles(t *testing.T) {
	root := t.TempDir()
	header := filepath.Join(root, "manager.h")
	source := filepath.Join(root, "manager.cpp")
	if err := os.WriteFile(header, []byte("class Manager {};\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("void Manager::run() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := openDB(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := storeParseResult(db, header, "cpp", &ParseResult{Classes: []Symbol{{Name: "Manager", QualifiedName: "Manager", Kind: "class", Line: 1, EndLine: 1}}}); err != nil {
		t.Fatal(err)
	}
	if err := storeParseResult(db, source, "cpp", &ParseResult{Functions: []Symbol{{Name: "run", QualifiedName: "Manager::run", Scope: "Manager", Kind: "function", Line: 1, EndLine: 1}}}); err != nil {
		t.Fatal(err)
	}
	if err := resolveSymbolKinds(db); err != nil {
		t.Fatal(err)
	}
	var kind string
	if err := db.QueryRow("SELECT kind FROM symbols WHERE qualified_name='Manager::run'").Scan(&kind); err != nil || kind != "method" {
		t.Fatalf("cross-file method kind = %q, err=%v", kind, err)
	}
}

func TestResolveCallCandidatesPreservesAmbiguity(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "sample.rs")
	if err := os.WriteFile(file, []byte("fn placeholder() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := openDB(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	result := &ParseResult{
		Calls: []Symbol{{Capture: "callee", Name: "run", RawText: "value.run", Receiver: "value", Resolution: "lexical", Confidence: 0.35, Line: 3}},
	}
	for i := 1; i <= 20; i++ {
		owner := "Type" + itoa(i)
		result.Functions = append(result.Functions, Symbol{Name: "run", QualifiedName: owner + "::run", Kind: "method", Line: i, EndLine: i, Scope: owner})
	}
	if err := storeParseResult(db, file, "rust", result); err != nil {
		t.Fatal(err)
	}
	if err := resolveCallCandidates(db); err != nil {
		t.Fatal(err)
	}
	var candidates int
	if err := db.QueryRow("SELECT COUNT(*) FROM call_candidates").Scan(&candidates); err != nil || candidates != 16 {
		t.Fatalf("candidate count = %d, err=%v", candidates, err)
	}
	var resolution string
	if err := db.QueryRow("SELECT resolution FROM calls").Scan(&resolution); err != nil || resolution != "candidate" {
		t.Fatalf("ambiguous call resolution = %q, err=%v", resolution, err)
	}
}

func TestChangeDetectionUsesContentNotMetadata(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "same-size.go")
	if err := os.WriteFile(file, []byte("alpha"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	db, err := openDB(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := storeParseResult(db, file, "go", &ParseResult{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("bravo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(file, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	changed, err := isFileChanged(db, file)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("same-size edit with preserved timestamp was not detected")
	}
}

func TestIndexedQueriesUseQualifiedEdgesAndExactRanges(t *testing.T) {
	root := t.TempDir()
	source := `package sample
type Box struct{}
func (b Box) Run() { helper() }
func helper() {}
func use() { b := Box{}; b.Run() }
`
	if err := os.WriteFile(filepath.Join(root, "sample.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	indexed, err := opIndex(CodeGraphInput{Path: root, Workers: 1})
	if err != nil || !strings.Contains(indexed, "1 files indexed") || !strings.Contains(indexed, "0 errors") {
		t.Fatalf("index failed: %q, err=%v", indexed, err)
	}
	find, err := opFind(CodeGraphInput{Path: root, Name: "Run"})
	if err != nil || !strings.Contains(find, "sample::Box::Run") || !strings.Contains(find, ":3-3") {
		t.Fatalf("find did not expose qualified range: %q, err=%v", find, err)
	}
	callers, err := opCallers(CodeGraphInput{Path: root, Name: "sample::Box::Run"})
	if err != nil || !strings.Contains(callers, "sample::use") || !strings.Contains(callers, "[exact 1.00]") {
		t.Fatalf("callers did not use qualified edge: %q, err=%v", callers, err)
	}
	callees, err := opCallees(CodeGraphInput{Path: root, Name: "sample::Box::Run", MaxResults: 100, MaxOutputChars: 32768})
	if err != nil || !strings.Contains(callees, "helper [exact 1.00]") {
		t.Fatalf("callees did not use exact function range: %q, err=%v", callees, err)
	}
	methods, err := opMethods(CodeGraphInput{Path: root, Name: "Box"})
	if err != nil || !strings.Contains(methods, "sample::Box::Run") || !strings.Contains(methods, ":3-3") {
		t.Fatalf("methods did not expose range: %q, err=%v", methods, err)
	}
	stats, err := opStats(CodeGraphInput{Path: root})
	if err != nil || !strings.Contains(stats, "Types: 1") || !strings.Contains(stats, "Candidate edges:") {
		t.Fatalf("stats missing graph-v2 counts: %q, err=%v", stats, err)
	}
}

func TestIndexReplacesChangedFileAtomicallyAndPurgesDeletedFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sample.go")
	write := func(source string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}

	write("package sample\nfunc Old() { TargetA() }\nfunc TargetA() {}\n")
	first, err := opIndex(CodeGraphInput{Path: root, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(first, "1 files indexed") || !strings.Contains(first, "0 errors") {
		t.Fatalf("unexpected first index result:\n%s", first)
	}

	write("package sample\nfunc New() { TargetB() }\nfunc TargetB() {}\n// size changed\n")
	second, err := opIndex(CodeGraphInput{Path: root, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(second, "1 files indexed") || !strings.Contains(second, "0 errors") {
		t.Fatalf("unexpected reindex result:\n%s", second)
	}

	db, err := openDB(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	assertCount := func(query string, want int, args ...any) {
		t.Helper()
		var got int
		if err := db.QueryRow(query, args...).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("query %q returned %d, want %d", query, got, want)
		}
	}
	assertCount("SELECT COUNT(*) FROM symbols WHERE name = ?", 0, "Old")
	assertCount("SELECT COUNT(*) FROM symbols WHERE name = ?", 1, "New")
	assertCount("SELECT COUNT(*) FROM calls WHERE callee_name = ?", 0, "TargetA")
	assertCount("SELECT COUNT(*) FROM calls WHERE callee_name = ?", 1, "TargetB")
	db.Close()

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	third, err := opIndex(CodeGraphInput{Path: root, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(third, "1 removed") || !strings.Contains(third, "0 errors") {
		t.Fatalf("unexpected delete reconciliation result:\n%s", third)
	}

	db, err = openDB(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	assertCount = func(query string, want int, args ...any) {
		t.Helper()
		var got int
		if err := db.QueryRow(query, args...).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("query %q returned %d, want %d", query, got, want)
		}
	}
	assertCount("SELECT COUNT(*) FROM files", 0)
	assertCount("SELECT COUNT(*) FROM symbols", 0)
	assertCount("SELECT COUNT(*) FROM calls", 0)
}

func TestStoreParseResultSavepointRestoresPreviousFileOnFailure(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sample.go")
	if err := os.WriteFile(path, []byte("package sample\n"), 0644); err != nil {
		t.Fatal(err)
	}
	db, err := openDB(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	original := &ParseResult{
		Classes: []Symbol{{Name: "Original", Line: 1}},
		Calls:   []Symbol{{Capture: "callee", Name: "TargetA", Line: 2}},
	}
	if err := storeParseResult(db, path, "go", original); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TRIGGER reject_broken_symbol
		BEFORE INSERT ON symbols
		WHEN NEW.name = 'Broken'
		BEGIN
			SELECT RAISE(FAIL, 'intentional test failure');
		END
	`); err != nil {
		t.Fatal(err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	broken := &ParseResult{
		Classes: []Symbol{{Name: "Broken", Line: 1}},
		Calls:   []Symbol{{Capture: "callee", Name: "TargetB", Line: 2}},
	}
	if err := storeParseResultTxAtomic(tx, "codegraph_test_file", path, "go", broken); err == nil {
		t.Fatal("expected the trigger to reject the replacement")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	assertCount := func(query string, want int, args ...any) {
		t.Helper()
		var got int
		if err := db.QueryRow(query, args...).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("query %q returned %d, want %d", query, got, want)
		}
	}
	assertCount("SELECT COUNT(*) FROM symbols WHERE name = ?", 1, "Original")
	assertCount("SELECT COUNT(*) FROM symbols WHERE name = ?", 0, "Broken")
	assertCount("SELECT COUNT(*) FROM calls WHERE callee_name = ?", 1, "TargetA")
	assertCount("SELECT COUNT(*) FROM calls WHERE callee_name = ?", 0, "TargetB")
}
