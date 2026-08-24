package codegraph

import "testing"

func TestAdvancedEmbeddedSemanticFacts(t *testing.T) {
	t.Run("rust", func(t *testing.T) {
		result, err := parseSource("rust", `
macro_rules! local_macro { () => {} }
trait Base {}
trait Extra {}
impl<T: Base> Extra for T {}
struct Product;
struct Wrapped;
impl std::ops::Deref for Wrapped {
    type Target = Product;
    fn deref(&self) -> &Self::Target { todo!() }
}
fn use_it() { local_macro!(); }
`)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Macros) != 1 || result.Macros[0].Name != "local_macro" {
			t.Fatalf("Rust macro definition facts: %#v", result.Macros)
		}
		macroCall := assertCall(t, result.Calls, "local_macro!")
		if macroCall.Name != "local_macro" {
			t.Fatalf("Rust macro invocation: %#v", macroCall)
		}
		foundTarget := false
		for _, alias := range result.Aliases {
			if alias.Name == "Target" && alias.Target == "Product" && alias.Owner != "" {
				foundTarget = true
			}
		}
		if !foundTarget {
			t.Fatalf("Rust associated Target fact: %#v", result.Aliases)
		}
		foundBlanket := false
		for _, relation := range result.Inheritance {
			if relation.ClassName == "@blanket:Base" && relation.ParentName == "Extra" && relation.Kind == "blanket_implements" {
				foundBlanket = true
			}
		}
		if !foundBlanket {
			t.Fatalf("Rust blanket implementation: %#v", result.Inheritance)
		}
	})

	t.Run("csharp-extension", func(t *testing.T) {
		result, err := parseSource("csharp", `
class Service {}
static class ServiceExtensions {
    public static int Run(this Service service, int count) { return count; }
}
`)
		if err != nil {
			t.Fatal(err)
		}
		extension := assertSymbol(t, result.Functions, "Run", "ServiceExtensions::Run", "method")
		if extension.ReturnType != "int" || extension.Arity != 2 || !csvContains(extension.Modifiers, "extension") {
			t.Fatalf("C# extension summary: %#v", extension)
		}
	})

	t.Run("java-method-reference", func(t *testing.T) {
		result, err := parseSource("java", `
class Example {
    void target() {}
    void use() { Runnable callback = this::target; callback.run(); }
}
`)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, variable := range result.Variables {
			if variable.Name == "callback" && variable.Kind == "callback" && variable.Target == "this::target" {
				found = true
			}
		}
		if !found {
			t.Fatalf("Java method reference facts: %#v", result.Variables)
		}
	})
}

func TestEmbeddedLanguageParsersPreserveStructure(t *testing.T) {
	tests := []struct {
		lang     string
		source   string
		validate func(*testing.T, *ParseResult)
	}{
		{"rust", `use std::fmt;
trait Runner { fn run(&self); }
struct Boxed<T> { value: T }
impl<T> Runner for Boxed<T> {
    fn run(&self) { helper(); self.work(); println!("x"); }
}
fn helper() { fmt::format(format_args!("x")); }
`, validateRustStructure},
		{"cpp", `#include <vector>
namespace demo {
template<class T> class Box : public Base { public: void run() override { helper(); this->work(); } };
template<class T> void Box<T>::other() { run(); }
void free_fn() { Box<int> b; b.run(); auto p = new Box<int>(); }
#if __CONTENTS(FEATURE_FLAG)
#endif
}
`, validateCPPStructure},
		{"python", `from os import path as osp
class Child(Base):
    @decorator
    def run(self):
        helper()
        self.work()
        def nested():
            osp.join("a", "b")
        nested()
`, validatePythonStructure},
		{"csharp", `using System;
namespace Demo;
class Child : Base, IFoo {
    public Child() { Helper(); this.Work(); var x = new Item(); }
    public int Value { get; set; }
}
`, validateCSharpStructure},
		{"java", `package demo;
import java.util.List;
record Child(int value) implements Runner {
    Child { helper(); this.work(); }
    public void run() { System.out.println(value); new Item(); }
}
`, validateJavaStructure},
	}

	for _, test := range tests {
		t.Run(test.lang, func(t *testing.T) {
			result, err := parseSource(test.lang, test.source)
			if err != nil {
				t.Fatal(err)
			}
			test.validate(t, result)
		})
	}
}

func validateRustStructure(t *testing.T, result *ParseResult) {
	assertSymbol(t, result.Classes, "Boxed", "Boxed", "struct")
	assertSymbol(t, result.Classes, "Runner", "Runner", "trait")
	assertSymbol(t, result.Functions, "run", "Boxed::run", "method")
	call := assertCall(t, result.Calls, "self.work")
	if call.Scope != "Boxed::run" || call.Receiver != "self" {
		t.Fatalf("Rust receiver call lost structure: %#v", call)
	}
	assertImport(t, result.Imports, "std::fmt")
	assertRelation(t, result.Inheritance, "Boxed", "Runner", "implements")
}

func validateCPPStructure(t *testing.T, result *ParseResult) {
	if len(result.Classes) != 1 {
		t.Fatalf("C++ template emitted duplicate/blank types: %#v", result.Classes)
	}
	assertSymbol(t, result.Classes, "Box", "demo::Box", "class")
	assertSymbol(t, result.Functions, "run", "demo::Box::run", "method")
	assertSymbol(t, result.Functions, "other", "demo::Box::other", "method")
	assertSymbol(t, result.Functions, "free_fn", "demo::free_fn", "function")
	call := assertCall(t, result.Calls, "this->work")
	if call.Scope != "demo::Box::run" || call.Receiver != "this" {
		t.Fatalf("C++ receiver call lost structure: %#v", call)
	}
	resolved := assertCall(t, result.Calls, "b.run")
	if resolved.QualifiedName != "demo::Box::run" || resolved.Resolution != "exact" {
		t.Fatalf("C++ local receiver type was not propagated: %#v", resolved)
	}
	internal := assertCall(t, result.Calls, "run")
	if internal.QualifiedName != "demo::Box::run" || internal.Resolution != "exact" {
		t.Fatalf("C++ bare same-owner call was not resolved: %#v", internal)
	}
	constructed := assertCall(t, result.Calls, "Box")
	if constructed.Name != "Box" || constructed.QualifiedName != "demo::Box" || constructed.Resolution != "exact" {
		t.Fatalf("C++ new-expression was not linked to its type: %#v", constructed)
	}
	for _, candidate := range result.Calls {
		if candidate.Name == "__CONTENTS" {
			t.Fatalf("preprocessor condition was indexed as a runtime call: %#v", candidate)
		}
	}
	assertRelation(t, result.Inheritance, "Box", "Base", "inherits")
}

func validatePythonStructure(t *testing.T, result *ParseResult) {
	if len(result.Functions) != 2 {
		t.Fatalf("Python decorator emitted duplicate/blank functions: %#v", result.Functions)
	}
	assertSymbol(t, result.Functions, "run", "Child::run", "method")
	assertSymbol(t, result.Functions, "nested", "Child::run::nested", "function")
	call := assertCall(t, result.Calls, "osp.join")
	if call.Scope != "Child::run::nested" || call.QualifiedName != "os::path::join" || call.Resolution != "exact" {
		t.Fatalf("Python alias/nested call lost structure: %#v", call)
	}
	assertCall(t, result.Calls, "self.work")
}

func validateCSharpStructure(t *testing.T, result *ParseResult) {
	assertSymbol(t, result.Classes, "Child", "Demo::Child", "class")
	assertSymbol(t, result.Functions, "Child", "Demo::Child::Child", "method")
	assertSymbol(t, result.Functions, "Value", "Demo::Child::Value", "property")
	created := assertCall(t, result.Calls, "Item")
	if created.Name != "Item" || created.Receiver != "" {
		t.Fatalf("C# object creation not normalized: %#v", created)
	}
	assertCall(t, result.Calls, "this.Work")
	assertRelation(t, result.Inheritance, "Child", "Base", "base")
}

func validateJavaStructure(t *testing.T, result *ParseResult) {
	assertSymbol(t, result.Classes, "Child", "demo::Child", "record")
	assertSymbol(t, result.Functions, "Child", "demo::Child::Child", "method")
	assertSymbol(t, result.Functions, "run", "demo::Child::run", "method")
	call := assertCall(t, result.Calls, "System.out.println")
	if call.Scope != "demo::Child::run" || call.QualifiedName != "System::out::println" {
		t.Fatalf("Java qualified call lost structure: %#v", call)
	}
	assertCall(t, result.Calls, "Item")
	assertRelation(t, result.Inheritance, "Child", "Runner", "implements")
}

func assertSymbol(t *testing.T, symbols []Symbol, name, qualified, kind string) Symbol {
	t.Helper()
	for _, symbol := range symbols {
		if symbol.Name == name && symbol.QualifiedName == qualified && symbol.Kind == kind {
			if symbol.EndLine < symbol.Line {
				t.Fatalf("invalid range for %s: %#v", qualified, symbol)
			}
			return symbol
		}
	}
	t.Fatalf("symbol %s (%s) not found in %#v", qualified, kind, symbols)
	return Symbol{}
}

func assertCall(t *testing.T, calls []Symbol, raw string) Symbol {
	t.Helper()
	for _, call := range calls {
		if call.RawText == raw {
			return call
		}
	}
	t.Fatalf("call %q not found in %#v", raw, calls)
	return Symbol{}
}

func assertImport(t *testing.T, imports []Symbol, name string) {
	t.Helper()
	for _, imported := range imports {
		if imported.Name == name {
			return
		}
	}
	t.Fatalf("import %q not found in %#v", name, imports)
}

func assertRelation(t *testing.T, relations []Inheritance, child, parent, kind string) {
	t.Helper()
	for _, relation := range relations {
		if relation.ClassName == child && relation.ParentName == parent && relation.Kind == kind {
			return
		}
	}
	t.Fatalf("relation %s -[%s]-> %s not found in %#v", child, kind, parent, relations)
}
