package codegraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSymbolsPaging(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.go")
	source := "package sample\nfunc Alpha() {}\nfunc Beta() {}\nfunc Gamma() {}\n"
	if err := os.WriteFile(path, []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	in := CodeGraphInput{Path: path, MaxResults: 1, MaxOutputChars: 10000}
	first, err := opSymbols(in)
	if err != nil {
		t.Fatal(err)
	}
	nameCount := 0
	for _, name := range []string{"Alpha", "Beta", "Gamma"} {
		if strings.Contains(first, name) {
			nameCount++
		}
	}
	if !strings.Contains(first, "offset=1") || nameCount != 1 {
		t.Fatalf("first page is not bounded or lacks continuation:\n%s", first)
	}
	in.Offset = 1
	second, err := opSymbols(in)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("offset did not advance the symbols page")
	}
}

func TestNormalizeCodeGraphLimitsAllowsLargePages(t *testing.T) {
	in := CodeGraphInput{MaxResults: hardCodeGraphMaxResults}
	if err := normalizeCodeGraphLimits(&in); err != nil {
		t.Fatal(err)
	}
	in.MaxResults++
	if err := normalizeCodeGraphLimits(&in); err == nil {
		t.Fatal("value above hard maximum should fail")
	}
}
