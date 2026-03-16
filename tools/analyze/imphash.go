package analyze

import (
	"crypto/md5"
	"debug/pe"
	"fmt"
	"strings"
)

// opImphash computes the import hash (imphash) of a PE file.
// Imphash is an MD5 of the normalized import table, used for malware family
// classification. Two binaries built from the same source typically share
// the same imphash. Standard in threat intelligence (VirusTotal, Mandiant).
//
// Algorithm: lowercase DLL name (without extension) + "." + function name,
// joined by commas, then MD5.
func opImphash(input AnalyzeInput) (string, error) {
	f, err := pe.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("not a valid PE file: %w", err)
	}
	defer f.Close()

	imports, err := f.ImportedSymbols()
	if err != nil {
		return "", fmt.Errorf("cannot read imports: %w", err)
	}
	if len(imports) == 0 {
		return "No imports found — imphash not applicable (static binary or no import table).", nil
	}

	var sb strings.Builder
	var normalized []string

	for _, sym := range imports {
		// Go's ImportedSymbols returns "FunctionName:DLLName" format
		parts := strings.SplitN(sym, ":", 2)
		if len(parts) != 2 {
			continue
		}
		fn := strings.ToLower(parts[0])
		dll := strings.ToLower(parts[1])

		// Strip common extensions (.dll, .sys, .ocx, .drv)
		for _, ext := range []string{".dll", ".sys", ".ocx", ".drv"} {
			dll = strings.TrimSuffix(dll, ext)
		}

		normalized = append(normalized, dll+"."+fn)
	}

	if len(normalized) == 0 {
		return "No normalizable imports found.", nil
	}

	joined := strings.Join(normalized, ",")
	hash := md5.Sum([]byte(joined))
	imphash := fmt.Sprintf("%x", hash)

	sb.WriteString(fmt.Sprintf("Imphash: %s\n", imphash))
	sb.WriteString(fmt.Sprintf("Imports: %d functions from %d entries\n", len(normalized), len(imports)))
	sb.WriteString(fmt.Sprintf("\nNormalized import list (first 20):\n"))

	shown := 0
	for _, n := range normalized {
		sb.WriteString(fmt.Sprintf("  %s\n", n))
		shown++
		if shown >= 20 {
			sb.WriteString(fmt.Sprintf("  ... +%d more\n", len(normalized)-shown))
			break
		}
	}

	sb.WriteString(fmt.Sprintf("\nUse this imphash to search VirusTotal, MISP, or other threat intel platforms\nfor binaries with the same import structure."))

	return sb.String(), nil
}
