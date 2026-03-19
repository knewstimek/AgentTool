package compress

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// maxSingleFileSize is the maximum size of a single file during extraction (1GB).
	maxSingleFileSize int64 = 1 << 30
	// maxTotalExtractSize is the upper limit for total extracted size (5GB).
	maxTotalExtractSize int64 = 5 << 30
)

type CompressInput struct {
	Sources []string `json:"sources" jsonschema:"List of absolute paths to files or directories to compress"`
	Output  string   `json:"output" jsonschema:"Absolute path for the output archive file (.zip or .tar.gz)"`
}

type CompressOutput struct {
	Result    string `json:"result"`
	FileCount int    `json:"file_count"`
}

type DecompressInput struct {
	Archive string `json:"archive" jsonschema:"Absolute path to the archive file (.zip or .tar.gz)"`
	Output  string `json:"output,omitempty" jsonschema:"Absolute path to the output directory. Defaults to archive's directory"`
}

type DecompressOutput struct {
	Result    string `json:"result"`
	FileCount int    `json:"file_count"`
}

func HandleCompress(ctx context.Context, req *mcp.CallToolRequest, input CompressInput) (*mcp.CallToolResult, CompressOutput, error) {
	if len(input.Sources) == 0 {
		return compressError("sources is required (at least one path)")
	}
	if input.Output == "" {
		return compressError("output is required")
	}
	if !filepath.IsAbs(input.Output) {
		return compressError("output must be an absolute path")
	}

	// Validate source paths
	for _, src := range input.Sources {
		if !filepath.IsAbs(src) {
			return compressError(fmt.Sprintf("source path must be absolute: %s", src))
		}
		if _, err := os.Stat(src); err != nil {
			if os.IsNotExist(err) {
				return compressError(fmt.Sprintf("source not found: %s", src))
			}
			return compressError(fmt.Sprintf("cannot access source: %v", err))
		}
	}

	// Create output directory
	if err := os.MkdirAll(filepath.Dir(input.Output), 0755); err != nil {
		return compressError(fmt.Sprintf("failed to create output directory: %v", err))
	}

	var count int
	var err error

	ext := strings.ToLower(input.Output)
	switch {
	case strings.HasSuffix(ext, ".tar.gz") || strings.HasSuffix(ext, ".tgz"):
		count, err = createTarGz(input.Output, input.Sources)
	case strings.HasSuffix(ext, ".zip"):
		count, err = createZip(input.Output, input.Sources)
	default:
		return compressError("unsupported format: use .zip or .tar.gz")
	}

	if err != nil {
		return compressError(fmt.Sprintf("compression failed: %v", err))
	}

	msg := fmt.Sprintf("OK: compressed %d files → %s", count, input.Output)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, CompressOutput{Result: msg, FileCount: count}, nil
}

func HandleDecompress(ctx context.Context, req *mcp.CallToolRequest, input DecompressInput) (*mcp.CallToolResult, DecompressOutput, error) {
	if input.Archive == "" {
		return decompressError("archive is required")
	}
	if input.Output == "" {
		return decompressError("output is required")
	}
	if !filepath.IsAbs(input.Archive) {
		return decompressError("archive must be an absolute path")
	}
	if !filepath.IsAbs(input.Output) {
		return decompressError("output must be an absolute path")
	}

	if _, err := os.Stat(input.Archive); err != nil {
		if os.IsNotExist(err) {
			return decompressError(fmt.Sprintf("archive not found: %s", input.Archive))
		}
		return decompressError(fmt.Sprintf("cannot access archive: %v", err))
	}

	if err := os.MkdirAll(input.Output, 0755); err != nil {
		return decompressError(fmt.Sprintf("failed to create output directory: %v", err))
	}

	var count, skippedSymlinks int
	var err error

	ext := strings.ToLower(input.Archive)
	switch {
	case strings.HasSuffix(ext, ".tar.gz") || strings.HasSuffix(ext, ".tgz"):
		count, skippedSymlinks, err = extractTarGz(input.Archive, input.Output)
	case strings.HasSuffix(ext, ".zip"):
		count, skippedSymlinks, err = extractZip(input.Archive, input.Output)
	default:
		return decompressError("unsupported format: use .zip or .tar.gz")
	}

	if err != nil {
		return decompressError(fmt.Sprintf("decompression failed: %v", err))
	}

	msg := fmt.Sprintf("OK: extracted %d files → %s", count, input.Output)
	if skippedSymlinks > 0 {
		msg += fmt.Sprintf(" (skipped %d symlinks)", skippedSymlinks)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, DecompressOutput{Result: msg, FileCount: count}, nil
}

// --- ZIP ---

func createZip(output string, sources []string) (int, error) {
	f, err := os.Create(output)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	w := zip.NewWriter(f)
	defer w.Close()

	count := 0
	for _, src := range sources {
		fi, err := os.Stat(src)
		if err != nil {
			return count, fmt.Errorf("cannot stat source: %w", err)
		}
		if fi.IsDir() {
			base := filepath.Dir(src)
			err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if info.IsDir() {
					return nil
				}
				rel, _ := filepath.Rel(base, path)
				return addFileToZip(w, path, filepath.ToSlash(rel), &count)
			})
			if err != nil {
				return count, err
			}
		} else {
			err := addFileToZip(w, src, filepath.Base(src), &count)
			if err != nil {
				return count, err
			}
		}
	}
	return count, nil
}

func addFileToZip(w *zip.Writer, filePath, archivePath string, count *int) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = archivePath
	header.Method = zip.Deflate

	writer, err := w.CreateHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, f)
	if err != nil {
		return err
	}

	*count++
	return nil
}

func extractZip(archive, outputDir string) (int, int, error) {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return 0, 0, err
	}
	defer r.Close()

	count := 0
	skippedSymlinks := 0
	var totalSize int64
	cleanOutputDir := filepath.Clean(outputDir) + string(os.PathSeparator)

	for _, f := range r.File {
		target := filepath.Join(outputDir, filepath.FromSlash(f.Name))

		// Zip Slip prevention: after filepath.Join resolves "../", verify the final path
		// is inside outputDir. The outputDir itself (directory entries) is also allowed.
		// Example: "../../etc/passwd" -> Join+Clean -> "/etc/passwd" -> outside outputDir -> skip
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), cleanOutputDir) &&
			filepath.Clean(target) != filepath.Clean(outputDir) {
			continue
		}

		// ZIP symlink: Go's archive/zip does not natively support reading symlink targets,
		// so they are always skipped regardless of allow_symlinks setting.
		// (Unlike tar, zip stores symlink targets as file content, making safe verification difficult)
		if f.FileInfo().Mode()&os.ModeSymlink != 0 {
			skippedSymlinks++
			continue
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0755)
			continue
		}

		// Zip Bomb prevention: pre-check total extracted size
		totalSize += int64(f.UncompressedSize64)
		if totalSize > maxTotalExtractSize {
			return count, skippedSymlinks, fmt.Errorf("total extracted size exceeds limit (%d bytes)", maxTotalExtractSize)
		}

		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return count, skippedSymlinks, err
		}

		if err := extractZipFile(f, target); err != nil {
			return count, skippedSymlinks, err
		}
		count++
	}
	return count, skippedSymlinks, nil
}

// extractZipFile extracts a single zip entry to the target path.
// Returns an error if maxSingleFileSize is exceeded (Zip Bomb prevention).
func extractZipFile(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	out, err := os.Create(target)
	if err != nil {
		return err
	}
	defer out.Close()

	// Zip Bomb prevention: single file size limit. Detect overflow with +1 byte.
	n, err := io.Copy(out, io.LimitReader(rc, maxSingleFileSize+1))
	if err != nil {
		return err
	}
	if n > maxSingleFileSize {
		return fmt.Errorf("file exceeds single file size limit (%d bytes): %s", maxSingleFileSize, target)
	}
	return nil
}

// --- TAR.GZ ---

func createTarGz(output string, sources []string) (int, error) {
	f, err := os.Create(output)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	count := 0
	for _, src := range sources {
		fi, err := os.Stat(src)
		if err != nil {
			return count, fmt.Errorf("cannot stat source: %w", err)
		}
		if fi.IsDir() {
			base := filepath.Dir(src)
			err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if info.IsDir() {
					return nil
				}
				rel, _ := filepath.Rel(base, path)
				return addFileToTar(tw, path, filepath.ToSlash(rel), info, &count)
			})
			if err != nil {
				return count, err
			}
		} else {
			err := addFileToTar(tw, src, filepath.Base(src), fi, &count)
			if err != nil {
				return count, err
			}
		}
	}
	return count, nil
}

func addFileToTar(tw *tar.Writer, filePath, archivePath string, info os.FileInfo, count *int) error {
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = archivePath

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(tw, f)
	if err != nil {
		return err
	}

	*count++
	return nil
}

// extractTarGz extracts a tar.gz archive. Returns (file count, skipped symlink count, error).
func extractTarGz(archive, outputDir string) (int, int, error) {
	f, err := os.Open(archive)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return 0, 0, err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	count := 0
	skippedSymlinks := 0
	var totalSize int64
	cleanOutputDir := filepath.Clean(outputDir) + string(os.PathSeparator)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, skippedSymlinks, err
		}

		target := filepath.Join(outputDir, filepath.FromSlash(header.Name))

		// Zip Slip prevention: after filepath.Join resolves "../", verify the final path
		// is inside outputDir. The outputDir itself (directory entries) is also allowed.
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), cleanOutputDir) &&
			filepath.Clean(target) != filepath.Clean(outputDir) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, 0755)
		case tar.TypeReg:
			// Zip Bomb prevention: pre-check total extracted size to prevent disk exhaustion attacks.
			totalSize += header.Size
			if totalSize > maxTotalExtractSize {
				return count, skippedSymlinks, fmt.Errorf("total extracted size exceeds limit (%d bytes)", maxTotalExtractSize)
			}

			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return count, skippedSymlinks, err
			}
			out, err := os.Create(target)
			if err != nil {
				return count, skippedSymlinks, err
			}
			// Zip Bomb prevention: read maxSize+1 bytes to detect overflow.
			// Exactly maxSize is OK; maxSize+1 means overflow -> error.
			n, copyErr := io.Copy(out, io.LimitReader(tr, maxSingleFileSize+1))
			out.Close()
			if copyErr != nil {
				return count, skippedSymlinks, copyErr
			}
			if n > maxSingleFileSize {
				return count, skippedSymlinks, fmt.Errorf("file exceeds single file size limit (%d bytes): %s", maxSingleFileSize, target)
			}
			count++
		case tar.TypeSymlink, tar.TypeLink:
			// Default (allow_symlinks=false): skip symlink/hardlink creation for security.
			// Can be enabled via set_config allow_symlinks=true, but even when enabled,
			// links targeting outside outputDir are skipped to prevent path traversal.
			if !common.GetAllowSymlinks() {
				skippedSymlinks++
				break
			}
			// Resolve symlink target to absolute path and verify it is inside outputDir.
			// Relative paths (e.g. "../sibling/file") are resolved relative to the symlink location.
			linkTarget := header.Linkname
			if !filepath.IsAbs(linkTarget) {
				linkTarget = filepath.Join(filepath.Dir(target), linkTarget)
			}
			linkTarget = filepath.Clean(linkTarget)
			if !strings.HasPrefix(linkTarget+string(os.PathSeparator), cleanOutputDir) &&
				linkTarget != filepath.Clean(outputDir) {
				skippedSymlinks++ // e.g. "../../etc/passwd" -> outside outputDir -> skip
				break
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return count, skippedSymlinks, err
			}
			os.Remove(target) // prevent conflict with existing file
			if header.Typeflag == tar.TypeSymlink {
				// symlink: use the original relative/absolute path as-is (resolved path is for validation only).
				// Safety is guaranteed since the resolved path was already verified to be inside outputDir.
				if err := os.Symlink(header.Linkname, target); err != nil {
					skippedSymlinks++ // graceful skip on insufficient permissions (e.g. Windows)
					break
				}
			} else {
				// hardlink: create with the resolved absolute path (guaranteed to be inside outputDir).
				if err := os.Link(linkTarget, target); err != nil {
					skippedSymlinks++
					break
				}
			}
			count++
		}
	}
	return count, skippedSymlinks, nil
}

// --- Register ---

func RegisterCompress(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "compress",
		Description: `Compresses files and directories into an archive.
Supports .zip and .tar.gz formats.
Output format is determined by the file extension.`,
	}, HandleCompress)
}

func RegisterDecompress(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "decompress",
		Description: `Extracts an archive to a directory.
Supports .zip and .tar.gz formats.
Includes Zip Slip and Zip Bomb protection. Symlinks are skipped for security.`,
	}, HandleDecompress)
}

func compressError(msg string) (*mcp.CallToolResult, CompressOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, CompressOutput{Result: msg}, nil
}

func decompressError(msg string) (*mcp.CallToolResult, DecompressOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, DecompressOutput{Result: msg}, nil
}
