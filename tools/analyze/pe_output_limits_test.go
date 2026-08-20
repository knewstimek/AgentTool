package analyze

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestPEInfoImportPagingAndOutputLimit(t *testing.T) {
	skipIfNoCrackme(t)
	result, err := opPEInfo(AnalyzeInput{
		FilePath: testCrackme, MaxResults: 1, MaxOutputChars: 4000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if utf8.RuneCountInString(result) > 4000 {
		t.Fatalf("pe_info exceeded output limit: %d", utf8.RuneCountInString(result))
	}
	if !strings.Contains(result, "More imports available") {
		t.Fatalf("missing import continuation hint:\n%s", result)
	}
}
