package codegraph

import "testing"

func TestParseGoSourcePreservesLanguageStructure(t *testing.T) {
	source := `package sample

import (
	"fmt"
	alias "strings"
)

type ID = string
type Box[T any] struct{ Value T }
type Runner interface { Run(string) error }

func Top(x string) string {
	fmt.Println(x)
	return alias.TrimSpace(x)
}

func (b *Box[T]) Run(s string) error {
	helper(s)
	return nil
}

func helper(string) {}

func use(r Runner) {
	b := Box[int]{}
	b.Run("value")
	r.Run("value")
}
`
	result, err := parseGoSource(source)
	if err != nil {
		t.Fatal(err)
	}

	types := make(map[string]Symbol)
	for _, symbol := range result.Classes {
		types[symbol.Name] = symbol
	}
	if types["ID"].Kind != "alias" {
		t.Fatalf("ID kind = %q, want alias", types["ID"].Kind)
	}
	if types["Box"].Kind != "struct" {
		t.Fatalf("Box kind = %q, want struct", types["Box"].Kind)
	}
	if types["Runner"].Kind != "interface" {
		t.Fatalf("Runner kind = %q, want interface", types["Runner"].Kind)
	}

	functions := make(map[string]Symbol)
	for _, symbol := range result.Functions {
		functions[symbol.QualifiedName] = symbol
	}
	method := functions["sample::Box::Run"]
	if method.Kind != "method" || method.Scope != "Box" || method.EndLine <= method.Line {
		t.Fatalf("generic receiver method was not preserved: %+v", method)
	}
	interfaceMethod := functions["sample::Runner::Run"]
	if interfaceMethod.Kind != "method" || interfaceMethod.Scope != "Runner" {
		t.Fatalf("interface method was not preserved: %+v", interfaceMethod)
	}

	imports := make(map[string]string)
	for _, symbol := range result.Imports {
		imports[symbol.QualifiedName] = symbol.Name
	}
	if imports["fmt"] != "fmt" || imports["alias"] != "strings" {
		t.Fatalf("imports were not expanded with aliases: %#v", imports)
	}

	calls := make(map[string]Symbol)
	for _, call := range result.Calls {
		calls[call.RawText] = call
	}
	if call := calls["fmt.Println"]; call.QualifiedName != "fmt::Println" || call.Resolution != "exact" {
		t.Fatalf("package selector call was not resolved: %+v", call)
	}
	if call := calls["alias.TrimSpace"]; call.QualifiedName != "strings::TrimSpace" || call.Receiver != "alias" {
		t.Fatalf("aliased import call was not resolved: %+v", call)
	}
	if call := calls["helper"]; call.QualifiedName != "sample::helper" || call.Scope != "sample::Box::Run" {
		t.Fatalf("direct call did not retain caller and target: %+v", call)
	}
	if call := calls["b.Run"]; call.QualifiedName != "sample::Box::Run" || call.Resolution != "exact" {
		t.Fatalf("local receiver type was not propagated: %+v", call)
	}
	if call := calls["r.Run"]; call.QualifiedName != "sample::Runner::Run" || call.Resolution != "exact" {
		t.Fatalf("interface parameter type was not propagated: %+v", call)
	}
}
