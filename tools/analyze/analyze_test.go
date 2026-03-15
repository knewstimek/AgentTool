package analyze

import (
	"fmt"
	"strings"
	"testing"
)

const testBinary = `C:\agent-tool-test\agent-tool.exe`

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
