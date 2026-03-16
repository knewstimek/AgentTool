package analyze

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"agent-tool/common"
)

const (
	defaultDiffMaxResults = 100
	maxDiffMaxResults     = 500
	diffChunkSize         = 64 * 1024 // 64KB comparison chunks
)

// opBinDiff compares two binary files byte-by-byte and reports differences.
// Useful for finding patched bytes, version differences, or tampered regions.
func opBinDiff(input AnalyzeInput) (string, error) {
	if input.FilePathB == "" {
		return "", fmt.Errorf("file_path_b is required for bin_diff (second file to compare)")
	}

	pathB := filepath.Clean(input.FilePathB)
	if !filepath.IsAbs(pathB) {
		return "", fmt.Errorf("file_path_b must be an absolute path")
	}

	// Symlink check on second file
	if !common.GetAllowSymlinks() {
		if lfi, err := os.Lstat(pathB); err == nil && lfi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlinks are not allowed for file_path_b (see set_config allow_symlinks)")
		}
	}

	fiB, err := os.Stat(pathB)
	if err != nil {
		return "", fmt.Errorf("cannot access file_path_b: %w", err)
	}
	if fiB.IsDir() {
		return "", fmt.Errorf("file_path_b is a directory, not a file")
	}
	maxSize := int64(common.GetMaxFileSize())
	if fiB.Size() > maxSize {
		return "", fmt.Errorf("file_path_b too large: %d bytes (max %d MB)", fiB.Size(), maxSize/(1024*1024))
	}

	fA, err := os.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("cannot open file A: %w", err)
	}
	defer fA.Close()

	fB, err := os.Open(pathB)
	if err != nil {
		return "", fmt.Errorf("cannot open file B: %w", err)
	}
	defer fB.Close()

	fiA, err := fA.Stat()
	if err != nil {
		return "", fmt.Errorf("cannot stat file A: %w", err)
	}
	sizeA := fiA.Size()
	sizeB := fiB.Size()

	maxRes := input.MaxResults
	if maxRes <= 0 {
		maxRes = defaultDiffMaxResults
	}
	if maxRes > maxDiffMaxResults {
		maxRes = maxDiffMaxResults
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("File A: %s (%d bytes)\n", input.FilePath, sizeA))
	sb.WriteString(fmt.Sprintf("File B: %s (%d bytes)\n", pathB, sizeB))

	if sizeA != sizeB {
		sb.WriteString(fmt.Sprintf("Size difference: %+d bytes\n", sizeB-sizeA))
	}

	// Compare byte by byte using chunked reads
	compareLen := sizeA
	if sizeB < compareLen {
		compareLen = sizeB
	}

	bufA := make([]byte, diffChunkSize)
	bufB := make([]byte, diffChunkSize)
	found := 0
	totalDiffs := 0

	sb.WriteString(fmt.Sprintf("\nDifferences (comparing first %d bytes):\n", compareLen))
	sb.WriteString(fmt.Sprintf("  %-12s %-8s %-8s\n", "Offset", "File A", "File B"))

	for off := int64(0); off < compareLen; off += diffChunkSize {
		readLen := diffChunkSize
		if off+int64(readLen) > compareLen {
			readLen = int(compareLen - off)
		}

		nA, _ := fA.ReadAt(bufA[:readLen], off)
		nB, _ := fB.ReadAt(bufB[:readLen], off)
		n := nA
		if nB < n {
			n = nB
		}

		for i := 0; i < n; i++ {
			if bufA[i] != bufB[i] {
				totalDiffs++
				if found < maxRes {
					sb.WriteString(fmt.Sprintf("  0x%08x   0x%02x     0x%02x\n",
						off+int64(i), bufA[i], bufB[i]))
					found++
				}
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\n(%d byte differences found in %d shared bytes)", totalDiffs, compareLen))
	if totalDiffs > maxRes {
		sb.WriteString(fmt.Sprintf(" — showing first %d", maxRes))
	}
	if sizeA != sizeB {
		extra := sizeA - sizeB
		if extra < 0 {
			extra = -extra
		}
		sb.WriteString(fmt.Sprintf("\n(%d bytes only in %s)",
			extra, func() string {
				if sizeA > sizeB {
					return "file A"
				}
				return "file B"
			}()))
	}

	return sb.String(), nil
}
