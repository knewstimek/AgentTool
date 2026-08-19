package common

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestIsBinaryExt(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{".codegraph.db", true},
		{"index.sqlite3", true},
		{".codegraph.db-wal", true},
		{"tree-sitter-cpp.wasm", true},
		{"model.safetensors", true},
		{"archive.tar.gz", true},
		// Text formats that must stay searchable
		{"icon.svg", false},
		{"cert.pem", false},
		{"main.ts", false}, // TypeScript, not MPEG transport stream
		{"notes.rtf", false},
		{"handler.go", false},
		{"Makefile", false},
		// Ambiguous extensions are left to the content sniff
		{"payload.dat", false},
		{"backup.bak", false},
	}
	for _, c := range cases {
		if got := IsBinaryExt(c.name); got != c.want {
			t.Errorf("IsBinaryExt(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIsBinaryContent(t *testing.T) {
	// UTF-16LE without BOM: NUL on every odd index
	utf16le := []byte{}
	for _, r := range "package main\nfunc main() {}\n" {
		utf16le = append(utf16le, byte(r), 0x00)
	}
	// Mixed ASCII + Hangul UTF-16LE: Hangul (U+AC00..) contributes no NUL,
	// so the NUL ratio drops but the parity skew stays 100%.
	mixed := []byte{}
	for _, r := range "id: 가나다라마바사 ok" {
		mixed = append(mixed, byte(r&0xFF), byte(r>>8))
	}

	cases := []struct {
		name   string
		sample []byte
		want   bool
	}{
		{"plain ascii", []byte("func main() {\n\treturn\n}\n"), false},
		{"utf8 hangul", []byte("함수 시작\n"), false},
		{"empty", []byte{}, false},
		{"utf16le bom", append([]byte{0xFF, 0xFE}, utf16le...), false},
		{"utf16be bom", []byte{0xFE, 0xFF, 0x00, 0x61, 0x00, 0x62}, false},
		{"utf16le no bom", utf16le, false},
		{"utf16le mixed hangul", mixed, false},
		{"elf header", []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}, true},
		{"scattered nuls", []byte{'a', 0x00, 0x00, 'b', 0x00, 'c', 0x00, 0x00, 0x00, 'd'}, true},
	}
	for _, c := range cases {
		if got := isBinaryContent(c.sample); got != c.want {
			t.Errorf("isBinaryContent(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

// A SQLite database is the case that motivated content sniffing: its text
// columns hold real identifiers, so extension-blind tools matched it.
func TestIsBinaryFileSQLite(t *testing.T) {
	dir := t.TempDir()
	header := append([]byte("SQLite format 3\x00"), bytes.Repeat([]byte{0x00}, 64)...)
	header = append(header, []byte("storeParseResultTx")...)
	header = append(header, bytes.Repeat([]byte{0x00, 0x0D, 0x00, 0x00, 0x2A, 0x00}, 40)...)

	// Unlisted extension: only the content sniff can catch it.
	path := filepath.Join(dir, "index.unknownext")
	if err := os.WriteFile(path, header, 0o600); err != nil {
		t.Fatal(err)
	}
	if !IsBinaryFile(path) {
		t.Error("IsBinaryFile(sqlite with unlisted ext) = false, want true")
	}

	textPath := filepath.Join(dir, "notes.unknownext")
	if err := os.WriteFile(textPath, []byte("storeParseResultTx is here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if IsBinaryFile(textPath) {
		t.Error("IsBinaryFile(text with unlisted ext) = true, want false")
	}

	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if IsBinaryFile(empty) {
		t.Error("IsBinaryFile(empty) = true, want false")
	}
}
