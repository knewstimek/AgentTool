package analyze

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// Rich header compiler ID to product name mapping (common entries).
// Source: various RE community resources.
var richProductNames = map[uint16]string{
	0:   "Unknown",
	1:   "Import0",
	2:   "Linker510",
	3:   "Cvtomf510",
	4:   "Linker600",
	5:   "Cvtomf600",
	6:   "Cvtres500",
	7:   "Utc11_Basic",
	8:   "Utc11_C",
	9:   "Utc12_Basic",
	10:  "Utc12_C",
	11:  "Utc12_CPP",
	12:  "AliasObj60",
	13:  "VisualBasic60",
	14:  "Masm613",
	15:  "Masm710",
	16:  "Linker511",
	17:  "Cvtomf511",
	18:  "Masm614",
	19:  "Linker512",
	20:  "Cvtomf512",
	21:  "Utc12_C_Std",
	22:  "Utc12_CPP_Std",
	23:  "Utc12_C_Book",
	24:  "Utc12_CPP_Book",
	25:  "Implib700",
	26:  "Cvtomf700",
	28:  "Linker622",
	29:  "Cvtomf622",
	30:  "Cvtres501",
	45:  "Utc12_C_DLL",
	47:  "Utc13_C",
	48:  "Utc13_CPP",
	83:  "Linker710",
	84:  "Cvtomf710",
	85:  "Linker800",
	86:  "Cvtomf800",
	93:  "Utc13_C_Std",
	94:  "Utc13_CPP_Std",
	102: "Utc14_C",
	103: "Utc14_CPP",
	128: "Cvtres700",
	158: "Linker900",
	170: "Masm800",
	171: "Masm900",
	175: "Utc15_C",
	176: "Utc15_CPP",
	177: "Utc15_CVTCIL_C",
	178: "Utc15_CVTCIL_CPP",
	187: "Utc16_C",
	188: "Utc16_CPP",
	199: "Linker1000",
	201: "Utc17_C",
	202: "Utc17_CPP",
	214: "Masm1000",
	217: "Utc18_C",
	218: "Utc18_CPP",
	255: "Linker1100",
	258: "Utc1900_C",
	259: "Utc1900_CPP",
	260: "Utc1900_CVTCIL_C",
	261: "Utc1900_CVTCIL_CPP",
}

// opRichHeader parses the PE Rich header — an undocumented Microsoft structure
// that records which compiler/linker tools were used to build each object file.
// Useful for build environment fingerprinting and attribution.
func opRichHeader(input AnalyzeInput) (string, error) {
	// Rich header sits between DOS stub and PE signature — always within first 4KB.
	// Read only what's needed instead of the entire file.
	f, err := os.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("cannot open file: %w", err)
	}
	defer f.Close()

	data := make([]byte, 4096)
	n, err := f.Read(data)
	if err != nil {
		return "", fmt.Errorf("cannot read file: %w", err)
	}
	data = data[:n]

	// Ends with "Rich" marker followed by XOR key.
	richIdx := -1
	for i := 0; i < len(data)-8; i++ {
		if string(data[i:i+4]) == "Rich" {
			richIdx = i
			break
		}
	}
	if richIdx < 0 {
		return "No Rich header found (not a Microsoft-compiled PE, or Rich header was stripped).", nil
	}

	// XOR key is the 4 bytes after "Rich"
	if richIdx+8 > len(data) {
		return "Rich header found but truncated.", nil
	}
	xorKey := binary.LittleEndian.Uint32(data[richIdx+4:])

	// Find "DanS" marker (start of Rich header, XOR'd with key)
	// "DanS" = 0x536E6144
	dansMarker := uint32(0x536E6144) ^ xorKey
	dansIdx := -1
	for i := 0; i < richIdx; i += 4 {
		if i+4 <= len(data) {
			val := binary.LittleEndian.Uint32(data[i:])
			if val == dansMarker {
				dansIdx = i
				break
			}
		}
	}
	if dansIdx < 0 {
		return "Rich header marker found but DanS start marker not found (corrupted?).", nil
	}

	var sb strings.Builder
	sb.WriteString("PE Rich Header:\n\n")
	sb.WriteString(fmt.Sprintf("XOR Key: 0x%08x\n", xorKey))
	sb.WriteString(fmt.Sprintf("Offset: 0x%x - 0x%x (%d bytes)\n\n", dansIdx, richIdx+8, richIdx+8-dansIdx))

	// Decode entries: skip DanS + 3 padding DWORDs (16 bytes total),
	// then pairs of (compID, count)
	entryStart := dansIdx + 16 // skip DanS + 3 null DWORDs
	sb.WriteString(fmt.Sprintf("  %-6s %-30s %-8s %s\n", "ProdID", "Product", "Version", "Count"))

	entryCount := 0
	for off := entryStart; off < richIdx; off += 8 {
		if off+8 > len(data) {
			break
		}
		compID := binary.LittleEndian.Uint32(data[off:]) ^ xorKey
		count := binary.LittleEndian.Uint32(data[off+4:]) ^ xorKey

		prodID := uint16(compID >> 16)
		buildVer := uint16(compID & 0xFFFF)

		prodName := richProductNames[prodID]
		if prodName == "" {
			prodName = fmt.Sprintf("Unknown_%d", prodID)
		}

		sb.WriteString(fmt.Sprintf("  %-6d %-30s %-8d %d\n", prodID, prodName, buildVer, count))
		entryCount++

		if entryCount >= 100 {
			sb.WriteString("  ... truncated\n")
			break
		}
	}

	sb.WriteString(fmt.Sprintf("\n(%d tool entries found)", entryCount))

	// Compute Rich header hash (MD5 of the raw Rich header region)
	// This is used for malware clustering similar to imphash
	if richIdx+8 <= len(data) && dansIdx >= 0 {
		richData := data[dansIdx : richIdx+8]
		richHash := md5Hex(richData)
		sb.WriteString(fmt.Sprintf("\nRich Header Hash (MD5): %s", richHash))
	}

	return sb.String(), nil
}

func md5Hex(data []byte) string {
	hash := md5.Sum(data)
	return fmt.Sprintf("%x", hash)
}
