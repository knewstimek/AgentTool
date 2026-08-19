package common

import (
	"os"
	"path/filepath"
	"testing"
)

func encodeUTF16(s string, littleEndian bool, bom bool) []byte {
	var out []byte
	if bom {
		if littleEndian {
			out = append(out, bomUTF16LE...)
		} else {
			out = append(out, bomUTF16BE...)
		}
	}
	for _, r := range s {
		lo, hi := byte(r&0xFF), byte(r>>8)
		if littleEndian {
			out = append(out, lo, hi)
		} else {
			out = append(out, hi, lo)
		}
	}
	return out
}

// UTF-16 must survive read, and a read/write round trip must not change the
// bytes on disk -- an edit that silently rewrote the file as UTF-8 would be
// worse than not supporting it at all.
func TestUTF16RoundTrip(t *testing.T) {
	dir := t.TempDir()
	text := "id NEEDLE 가나다 tail\n"

	cases := []struct {
		name         string
		littleEndian bool
		bom          bool
		wantCharset  string
	}{
		{"le-bom", true, true, "UTF-16LE"},
		{"be-bom", false, true, "UTF-16BE"},
		{"le-nobom", true, false, "UTF-16LE"},
		{"be-nobom", false, false, "UTF-16BE"},
	}
	for _, c := range cases {
		raw := encodeUTF16(text, c.littleEndian, c.bom)
		path := filepath.Join(dir, c.name+".txt")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}

		got, info, err := ReadFileWithEncoding(path, "")
		if err != nil {
			t.Errorf("%s: read failed: %v", c.name, err)
			continue
		}
		if got != text {
			t.Errorf("%s: decoded %q, want %q", c.name, got, text)
		}
		if info.Charset != c.wantCharset {
			t.Errorf("%s: charset %q, want %q", c.name, info.Charset, c.wantCharset)
		}
		if info.HasBOM != c.bom {
			t.Errorf("%s: HasBOM %v, want %v", c.name, info.HasBOM, c.bom)
		}
		if w := EncodingWarning(info); w != "" {
			t.Errorf("%s: unexpected warning %q", c.name, w)
		}

		if err := WriteFileWithEncoding(path, got, info); err != nil {
			t.Errorf("%s: write failed: %v", c.name, err)
			continue
		}
		after, _ := os.ReadFile(path)
		if string(after) != string(raw) {
			t.Errorf("%s: round trip changed bytes (%d -> %d)", c.name, len(raw), len(after))
		}
	}
}

// chardet reports ~11-33% confidence on plain ASCII because nothing
// distinguishes it from Latin-1. That used to warn on over half the files in
// a repo; valid UTF-8 is proof, so it must not warn at all.
func TestASCIINoWarning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.go")
	if err := os.WriteFile(path, []byte("package main\n\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, info, err := ReadFileWithEncoding(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if info.Charset != "UTF-8" {
		t.Errorf("charset = %q, want UTF-8", info.Charset)
	}
	if w := EncodingWarning(info); w != "" {
		t.Errorf("plain ASCII warned: %q", w)
	}
}

// The UTF-8 fast path must not swallow legacy encodings: their multi-byte
// sequences are invalid UTF-8, so chardet still gets its turn.
func TestLegacyEncodingStillDetected(t *testing.T) {
	dir := t.TempDir()
	// EUC-KR for a Hangul sentence, repeated so chardet has enough signal.
	euckr := []byte{}
	for i := 0; i < 40; i++ {
		euckr = append(euckr, 0xC7, 0xD1, 0xB1, 0xDB, 0x20, 0xC5, 0xD7, 0xBD, 0xBA, 0xC6, 0xAE, 0x0A)
	}
	path := filepath.Join(dir, "legacy.txt")
	if err := os.WriteFile(path, euckr, 0o600); err != nil {
		t.Fatal(err)
	}
	got, info, err := ReadFileWithEncoding(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if info.Charset == "UTF-8" {
		t.Errorf("EUC-KR file read as UTF-8 (charset=%q, source=%q)", info.Charset, info.UsedSource)
	}
	if got == string(euckr) {
		t.Error("EUC-KR content was not decoded")
	}
}

// An .editorconfig charset is an explicit statement of intent and still wins.
func TestHintBeatsUTF8FastPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hinted.txt")
	if err := os.WriteFile(path, []byte("plain ascii body\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, info, err := ReadFileWithEncoding(path, "euc-kr")
	if err != nil {
		t.Fatal(err)
	}
	if info.Charset != "EUC-KR" || info.UsedSource != "hint" {
		t.Errorf("charset=%q source=%q, want EUC-KR/hint", info.Charset, info.UsedSource)
	}
}
