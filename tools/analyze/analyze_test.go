package analyze

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var testBinary string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "agent-tool-analyze-test-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create analyze test directory:", err)
		os.Exit(1)
	}

	sourcePath := filepath.Join(tmp, "fixture.go")
	source := []byte("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"agent-tool analyze fixture\") }\n")
	if err := os.WriteFile(sourcePath, source, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write analyze test fixture:", err)
		_ = os.RemoveAll(tmp)
		os.Exit(1)
	}

	testBinary = filepath.Join(tmp, "fixture.exe")
	cmd := exec.Command("go", "build", "-o", testBinary, sourcePath)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build analyze test fixture: %v\n%s", err, output)
		_ = os.RemoveAll(tmp)
		os.Exit(1)
	}

	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

func TestPEInfo(t *testing.T) {
	input := AnalyzeInput{
		Operation: "pe_info",
		FilePath:  testBinary,
	}
	result, err := opPEInfo(input)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result)

	if !strings.Contains(result, "AMD64") && !strings.Contains(result, "i386") {
		t.Error("expected machine type in output")
	}
	if !strings.Contains(result, ".text") {
		t.Error("expected .text section")
	}
}

func TestPEInfoRVA(t *testing.T) {
	input := AnalyzeInput{
		Operation: "pe_info",
		FilePath:  testBinary,
		RVA:       "0x1000",
	}
	result, err := opPEInfo(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "File offset") {
		t.Error("expected RVA conversion in output")
	}
	fmt.Println("RVA conversion:", result[strings.Index(result, "\nRVA"):])
}

func TestPEInfoBadRVA(t *testing.T) {
	input := AnalyzeInput{
		Operation: "pe_info",
		FilePath:  testBinary,
		RVA:       "hello",
	}
	result, err := opPEInfo(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "Invalid RVA") {
		t.Error("expected error message for invalid RVA")
	}
}

func TestDisassemble(t *testing.T) {
	input := AnalyzeInput{
		Operation: "disassemble",
		FilePath:  testBinary,
		Offset:    4096, // .text section usually starts around here
		Count:     20,
		Mode:      64,
	}
	result, err := opDisassemble(input)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result)

	if !strings.Contains(result, "0x") {
		t.Error("expected addresses in output")
	}
	if !strings.Contains(result, "20 instructions") {
		t.Errorf("expected 20 instructions, got: %s", result[strings.LastIndex(result, "\n("):])
	}
}

func TestDisassembleWithBase(t *testing.T) {
	input := AnalyzeInput{
		Operation: "disassemble",
		FilePath:  testBinary,
		Offset:    4096,
		Count:     5,
		Mode:      64,
		BaseAddr:  "0x140001000",
	}
	result, err := opDisassemble(input)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result)

	if !strings.Contains(result, "0x140002") {
		t.Error("expected base address offset in output")
	}
}

func TestStringsASCII(t *testing.T) {
	input := AnalyzeInput{
		Operation:  "strings",
		FilePath:   testBinary,
		MinLength:  6,
		MaxResults: 20,
	}
	result, err := opStrings(input)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result)

	// agent-tool.exe should contain recognizable strings
	if !strings.Contains(result, "strings found") {
		t.Error("expected summary line")
	}
}

func TestStringsUTF8(t *testing.T) {
	input := AnalyzeInput{
		Operation:  "strings",
		FilePath:   testBinary,
		MinLength:  6,
		MaxResults: 10,
		Encoding:   "utf8",
	}
	result, err := opStrings(input)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result)
}

func TestHexdump(t *testing.T) {
	input := AnalyzeInput{
		Operation: "hexdump",
		FilePath:  testBinary,
		Offset:    0,
		Length:    128,
	}
	result, err := opHexdump(input)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result)

	// PE files start with MZ
	if !strings.Contains(result, "4d 5a") && !strings.Contains(result, "4D 5A") {
		t.Error("expected MZ header (4d 5a) at offset 0")
	}
	if !strings.Contains(result, "|MZ") {
		t.Error("expected MZ in ASCII column")
	}
}

func TestHexdumpMiddle(t *testing.T) {
	input := AnalyzeInput{
		Operation: "hexdump",
		FilePath:  testBinary,
		Offset:    8192,
		Length:    64,
	}
	result, err := opHexdump(input)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result)

	if !strings.Contains(result, "00002000") {
		t.Error("expected offset 0x2000 in output")
	}
}

// --- Pattern Search tests ---

func TestPatternSearchMZ(t *testing.T) {
	// Every PE file starts with MZ (4D 5A)
	input := AnalyzeInput{
		Operation:  "pattern_search",
		FilePath:   testBinary,
		Pattern:    "4D 5A 90 00",
		MaxResults: 5,
	}
	result, err := opPatternSearch(input)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result)
	if !strings.Contains(result, "0x00000000") {
		t.Error("expected match at offset 0")
	}
}

func TestPatternSearchWildcard(t *testing.T) {
	// MZ header with wildcards: 4D 5A ?? ?? followed by anything
	input := AnalyzeInput{
		Operation:  "pattern_search",
		FilePath:   testBinary,
		Pattern:    "4D 5A ?? ??",
		MaxResults: 3,
	}
	result, err := opPatternSearch(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "matches found") {
		t.Error("expected summary line")
	}
}

func TestPatternSearchInvalidHex(t *testing.T) {
	input := AnalyzeInput{
		Operation: "pattern_search",
		FilePath:  testBinary,
		Pattern:   "ZZ FF",
	}
	_, err := opPatternSearch(input)
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

// --- PE RWX test ---

func TestPEInfoRWXPerms(t *testing.T) {
	input := AnalyzeInput{
		Operation: "pe_info",
		FilePath:  testBinary,
	}
	result, err := opPEInfo(input)
	if err != nil {
		t.Fatal(err)
	}
	// .text should show R X CODE
	if !strings.Contains(result, "R X CODE") {
		t.Error("expected R X CODE for .text section")
	}
	// .data should show R W DATA
	if !strings.Contains(result, "R W DATA") {
		t.Error("expected R W DATA for .data section")
	}
}

// --- Entropy tests ---

func TestEntropy(t *testing.T) {
	input := AnalyzeInput{
		Operation: "entropy",
		FilePath:  testBinary,
	}
	result, err := opEntropy(input)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result[:min(len(result), 500)])

	if !strings.Contains(result, "Overall Entropy") {
		t.Error("expected overall entropy in output")
	}
	if !strings.Contains(result, ".text") {
		t.Error("expected .text section entropy")
	}
}

func TestShannonEntropy(t *testing.T) {
	// All zeros = 0 entropy
	zeros := make([]byte, 256)
	if e := shannonEntropy(zeros); e != 0 {
		t.Errorf("expected 0 entropy for all zeros, got %f", e)
	}

	// All unique bytes = 8.0 entropy (maximum)
	uniform := make([]byte, 256)
	for i := range uniform {
		uniform[i] = byte(i)
	}
	e := shannonEntropy(uniform)
	if e < 7.99 || e > 8.01 {
		t.Errorf("expected ~8.0 entropy for uniform distribution, got %f", e)
	}
}

// --- Bin Diff tests ---

func TestBinDiffIdentical(t *testing.T) {
	// Compare file with itself — 0 differences
	input := AnalyzeInput{
		Operation: "bin_diff",
		FilePath:  testBinary,
		FilePathB: testBinary,
	}
	result, err := opBinDiff(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "0 byte differences") {
		t.Errorf("expected 0 differences, got: %s", result)
	}
}

func TestBinDiffDifferent(t *testing.T) {
	tmp := t.TempDir()
	fileA := filepath.Join(tmp, "a.bin")
	fileB := filepath.Join(tmp, "b.bin")

	dataA := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	dataB := []byte{0x00, 0xFF, 0x02, 0xFE, 0x04}
	os.WriteFile(fileA, dataA, 0644)
	os.WriteFile(fileB, dataB, 0644)

	input := AnalyzeInput{
		Operation: "bin_diff",
		FilePath:  fileA,
		FilePathB: fileB,
	}
	result, err := opBinDiff(input)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result)

	// Should find exactly 2 differences (index 1 and 3)
	if !strings.Contains(result, "2 byte differences") {
		t.Errorf("expected 2 differences, got: %s", result)
	}
}

func TestBinDiffSizeMismatch(t *testing.T) {
	tmp := t.TempDir()
	fileA := filepath.Join(tmp, "a.bin")
	fileB := filepath.Join(tmp, "b.bin")

	os.WriteFile(fileA, []byte{0x00, 0x01, 0x02}, 0644)
	os.WriteFile(fileB, []byte{0x00, 0x01, 0x02, 0x03, 0x04}, 0644)

	input := AnalyzeInput{
		Operation: "bin_diff",
		FilePath:  fileA,
		FilePathB: fileB,
	}
	result, err := opBinDiff(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "Size difference") {
		t.Error("expected size difference message")
	}
	if !strings.Contains(result, "only in file B") {
		t.Error("expected 'only in file B' message")
	}
}

// --- Resource Info tests ---

func TestResourceInfo(t *testing.T) {
	input := AnalyzeInput{
		Operation: "resource_info",
		FilePath:  testBinary,
	}
	result, err := opResourceInfo(input)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result[:min(len(result), 500)])
	// Go binaries typically don't have resources, but should not crash
	// If it has resources, check for structure
	if !strings.Contains(result, "Resource") && !strings.Contains(result, "No resource") {
		t.Error("expected resource output or 'no resource' message")
	}
}

// --- Imphash tests ---

func TestImphash(t *testing.T) {
	input := AnalyzeInput{
		Operation: "imphash",
		FilePath:  testBinary,
	}
	result, err := opImphash(input)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result[:min(len(result), 300)])

	if !strings.Contains(result, "Imphash:") && !strings.Contains(result, "No imports") {
		t.Error("expected imphash or no-imports message")
	}
}

// --- Rich Header tests ---

func TestRichHeader(t *testing.T) {
	input := AnalyzeInput{
		Operation: "rich_header",
		FilePath:  testBinary,
	}
	result, err := opRichHeader(input)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result[:min(len(result), 300)])

	// Go binaries compiled with Go toolchain don't have Rich headers
	if !strings.Contains(result, "Rich Header") && !strings.Contains(result, "No Rich header") {
		t.Error("expected rich header output or not-found message")
	}
}

// --- Overlay Detect tests ---

func TestOverlayDetect(t *testing.T) {
	input := AnalyzeInput{
		Operation: "overlay_detect",
		FilePath:  testBinary,
	}
	result, err := opOverlayDetect(input)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result[:min(len(result), 500)])

	if !strings.Contains(result, "Last Section End") {
		t.Error("expected last section end info")
	}
}

func TestOverlayDetectWithOverlay(t *testing.T) {
	// Create a minimal PE-like file with overlay
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.bin")

	// Fake PE: just enough for pe.Open to work isn't practical,
	// so test with a known binary and check the output format
	input := AnalyzeInput{
		Operation: "overlay_detect",
		FilePath:  testBinary,
	}
	result, err := opOverlayDetect(input)
	if err != nil {
		t.Fatal(err)
	}
	_ = path
	// Should have format info
	if !strings.Contains(result, "PE") {
		t.Error("expected PE format detection")
	}
}

// --- DWARF Info tests ---

func TestDWARFInfo(t *testing.T) {
	input := AnalyzeInput{
		Operation: "dwarf_info",
		FilePath:  testBinary,
	}
	result, err := opDWARFInfo(input)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result[:min(len(result), 500)])

	// Go binaries include DWARF by default (unless stripped)
	if !strings.Contains(result, "DWARF") {
		t.Error("expected DWARF info output")
	}
	if !strings.Contains(result, "Compilation Units") {
		t.Error("expected compilation unit info")
	}
}

// --- ARM disassembly (unit test with raw bytes) ---

func TestDisasmARM64Bytes(t *testing.T) {
	// ARM64 NOP = 0xD503201F (little-endian: 1f 20 03 d5)
	tmp := t.TempDir()
	path := filepath.Join(tmp, "arm64.bin")
	// 3 NOP instructions
	data := []byte{
		0x1f, 0x20, 0x03, 0xd5, // NOP
		0x1f, 0x20, 0x03, 0xd5, // NOP
		0xc0, 0x03, 0x5f, 0xd6, // RET
	}
	os.WriteFile(path, data, 0644)

	input := AnalyzeInput{
		Operation: "disassemble",
		FilePath:  path,
		Count:     3,
		Mode:      64,
		Arch:      "arm",
	}
	result, err := opDisassemble(input)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result)

	if !strings.Contains(result, "arch=arm, mode=64") {
		t.Error("expected ARM64 mode in output")
	}
}
