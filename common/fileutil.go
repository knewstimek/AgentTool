package common

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/saintfish/chardet"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/ianaindex"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// DefaultMaxFileSize is the default maximum file size (100MB). RE targets such
// as game DLLs/EXEs routinely exceed 50MB, so the limit is generous; tune it
// per-session with set_config max_file_size_mb.
const DefaultMaxFileSize int64 = 100 * 1024 * 1024

// chardetSampleSize is the maximum number of bytes used for encoding detection.
// chardet does not need the entire file; a sample from the beginning is sufficient.
const chardetSampleSize = 64 * 1024 // 64KB

// EncodingInfo holds encoding information for a file.
type EncodingInfo struct {
	Charset    string // IANA name: "UTF-8", "EUC-KR", "Shift_JIS", etc.
	HasBOM     bool   // whether UTF-8 BOM is present
	Confidence int    // chardet detection confidence (0-100). 100 when hint/BOM/fallback is used.
	UsedSource string // encoding decision source: "bom", "hint", "chardet", "fallback"
}

var (
	// fallbackEncoding is the fallback encoding used when chardet detection fails.
	fallbackEncoding   = "UTF-8"
	fallbackMu         sync.RWMutex
	// encodingWarnings controls whether encoding detection warning messages are shown.
	encodingWarnings   = true
	encodingWarningsMu sync.RWMutex
	// maxFileSize is the maximum file size allowed by ReadFileWithEncoding.
	// Can be changed at runtime via set_config max_file_size.
	maxFileSize   = DefaultMaxFileSize
	maxFileSizeMu sync.RWMutex
	// allowSymlinks controls whether symlink creation is allowed during archive extraction.
	// Default false (skipped for security). Can be changed via set_config allow_symlinks.
	allowSymlinks   = false
	allowSymlinksMu sync.RWMutex
	// workspace is the default working directory.
	// Used instead of os.Getwd() when path is not specified in glob, etc.
	// Can be changed at runtime via set_config workspace.
	workspace   string
	workspaceMu sync.RWMutex
)

// GetFallbackEncoding returns the current fallback encoding in a thread-safe manner.
func GetFallbackEncoding() string {
	fallbackMu.RLock()
	defer fallbackMu.RUnlock()
	return fallbackEncoding
}

// SetFallbackEncoding sets the fallback encoding in a thread-safe manner.
func SetFallbackEncoding(enc string) {
	fallbackMu.Lock()
	defer fallbackMu.Unlock()
	fallbackEncoding = enc
}

// GetEncodingWarnings returns whether encoding warnings are enabled.
func GetEncodingWarnings() bool {
	encodingWarningsMu.RLock()
	defer encodingWarningsMu.RUnlock()
	return encodingWarnings
}

// SetEncodingWarnings sets whether encoding warnings are enabled.
func SetEncodingWarnings(enabled bool) {
	encodingWarningsMu.Lock()
	defer encodingWarningsMu.Unlock()
	encodingWarnings = enabled
}

// GetMaxFileSize returns the current maximum file size limit.
func GetMaxFileSize() int64 {
	maxFileSizeMu.RLock()
	defer maxFileSizeMu.RUnlock()
	return maxFileSize
}

// SetMaxFileSize changes the maximum file size limit. Minimum 1MB.
func SetMaxFileSize(size int64) {
	if size < 1*1024*1024 {
		size = 1 * 1024 * 1024
	}
	maxFileSizeMu.Lock()
	defer maxFileSizeMu.Unlock()
	maxFileSize = size
}

// GetAllowSymlinks returns whether symlinks are allowed.
func GetAllowSymlinks() bool {
	allowSymlinksMu.RLock()
	defer allowSymlinksMu.RUnlock()
	return allowSymlinks
}

// SetAllowSymlinks sets whether symlinks are allowed.
func SetAllowSymlinks(allow bool) {
	allowSymlinksMu.Lock()
	defer allowSymlinksMu.Unlock()
	allowSymlinks = allow
}

// GetWorkspace returns the current workspace path.
// An empty string means it is not set.
func GetWorkspace() string {
	workspaceMu.RLock()
	defer workspaceMu.RUnlock()
	return workspace
}

// SetWorkspace sets the workspace path.
func SetWorkspace(path string) {
	workspaceMu.Lock()
	defer workspaceMu.Unlock()
	workspace = path
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// ReadFileWithEncoding reads a file and returns UTF-8 text along with encoding info.
// If hintCharset is non-empty (e.g. from .editorconfig), it takes highest priority.
func ReadFileWithEncoding(path string, hintCharset string) (string, EncodingInfo, error) {
	// symlink check: block symlinks if allow_symlinks is false
	if !GetAllowSymlinks() {
		if lfi, err := os.Lstat(path); err == nil && lfi.Mode()&os.ModeSymlink != 0 {
			return "", EncodingInfo{}, fmt.Errorf("symlink not allowed: %s (enable via set_config allow_symlinks=true)", path)
		}
	}

	// OOM prevention: pre-check file size
	limit := GetMaxFileSize()
	fi, err := os.Stat(path)
	if err != nil {
		return "", EncodingInfo{}, fmt.Errorf("failed to access file: %w", err)
	}
	if fi.Size() > limit {
		return "", EncodingInfo{}, fmt.Errorf("file too large (%d bytes, max %d bytes). Use set_config max_file_size_mb to adjust the limit", fi.Size(), limit)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return "", EncodingInfo{}, fmt.Errorf("failed to read file: %w", err)
	}

	info := EncodingInfo{Charset: "UTF-8", Confidence: 100, UsedSource: "bom"}

	// Check for UTF-8 BOM (BOM always takes highest priority)
	if bytes.HasPrefix(raw, utf8BOM) {
		info.HasBOM = true
		raw = raw[len(utf8BOM):]
		return string(raw), info, nil
	}

	// UTF-16 BOM. The BOM bytes are stripped here and re-added on write, so the
	// IgnoreBOM decoders below never leak a U+FEFF into the returned text.
	// UTF-32LE starts with the UTF-16LE BOM, so it has to be excluded first.
	if bytes.HasPrefix(raw, bomUTF16LE) && !bytes.HasPrefix(raw, bomUTF32LE) {
		info.HasBOM = true
		info.Charset = "UTF-16LE"
		return decodeUTF16(raw[len(bomUTF16LE):], true, info)
	}
	if bytes.HasPrefix(raw, bomUTF16BE) {
		info.HasBOM = true
		info.Charset = "UTF-16BE"
		return decodeUTF16(raw[len(bomUTF16BE):], false, info)
	}

	// Empty file
	if len(raw) == 0 {
		info.UsedSource = "fallback"
		return "", info, nil
	}

	// Encoding decision priority (BOMs already handled above):
	// 1. .editorconfig charset hint (hintCharset)
	// 2. BOM-less UTF-16 (NUL parity heuristic)
	// 3. utf8.Valid -- proof rather than a guess, so it outranks chardet
	// 4. chardet auto-detection (Confidence >= 50)
	// 5. FallbackEncoding (default UTF-8, changeable via CLI)

	charset := ""

	// 1. Hint charset
	if hintCharset != "" {
		charset = normalizeCharsetName(hintCharset)
		info.Confidence = 100
		info.UsedSource = "hint"
	}

	sample := raw
	if len(sample) > chardetSampleSize {
		sample = sample[:chardetSampleSize]
	}

	// 2. BOM-less UTF-16. chardet does not flag it, so without this the file
	// falls through to UTF-8 and every character reads with a NUL wedged
	// beside it -- searches and edits silently miss.
	if charset == "" {
		if littleEndian, ok := utf16Kind(sample); ok {
			if littleEndian {
				info.Charset = "UTF-16LE"
			} else {
				info.Charset = "UTF-16BE"
			}
			return decodeUTF16(raw, littleEndian, info)
		}
	}

	// 3. Valid UTF-8 is proof, not a guess -- decoding cannot go wrong, so this
	// outranks chardet and carries no warning. It matters most for plain ASCII:
	// chardet has nothing to distinguish it from Latin-1 and reports ~11-33%
	// confidence, which used to drop every such file into the fallback branch
	// and attach a low-confidence warning to over half the files in a repo.
	// Non-UTF-8 encodings (EUC-KR, Shift_JIS, GBK, CP1252) fail utf8.Valid on
	// their multi-byte sequences, so they are not swallowed here.
	if charset == "" && utf8.Valid(raw) {
		charset = "UTF-8"
		info.Confidence = 100
		info.UsedSource = "utf8"
	}

	// 4. chardet detection (uses only a front sample — full file not needed)
	if charset == "" {
		detector := chardet.NewTextDetector()
		result, detectErr := detector.DetectBest(sample)
		if detectErr == nil && result.Confidence >= 50 {
			charset = normalizeCharsetName(result.Charset)
			info.Confidence = result.Confidence
			info.UsedSource = "chardet"
		}
	}

	// 5. Fallback
	if charset == "" {
		charset = normalizeCharsetName(GetFallbackEncoding())
		info.Confidence = 0
		info.UsedSource = "fallback"
	}

	info.Charset = charset

	// Return as-is if UTF-8
	if info.Charset == "UTF-8" {
		return string(raw), info, nil
	}

	// Decode to UTF-8 if a different encoding
	enc, err := ianaindex.IANA.Encoding(info.Charset)
	if err != nil || enc == nil {
		info.Charset = "UTF-8"
		return string(raw), info, nil
	}

	decoded, err := decodeBytes(raw, enc)
	if err != nil {
		info.Charset = "UTF-8"
		return string(raw), info, nil
	}

	return decoded, info, nil
}

// utf16Encoding returns the UTF-16 codec for the given byte order. IgnoreBOM
// is deliberate on both sides: ReadFileWithEncoding strips the BOM before
// decoding and WriteFileWithEncoding re-attaches it, matching how the UTF-8
// BOM is handled and keeping U+FEFF out of the decoded text.
func utf16Encoding(littleEndian bool) encoding.Encoding {
	if littleEndian {
		return unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	}
	return unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM)
}

// decodeUTF16 decodes BOM-stripped UTF-16 bytes, falling back to the raw bytes
// if the codec rejects them (a truncated surrogate, say) so a bad guess degrades
// to the old behaviour instead of failing the read.
func decodeUTF16(raw []byte, littleEndian bool, info EncodingInfo) (string, EncodingInfo, error) {
	if info.UsedSource == "" || info.UsedSource == "bom" {
		if !info.HasBOM {
			info.UsedSource = "utf16-heuristic"
		}
	}
	info.Confidence = 100
	decoded, err := decodeBytes(raw, utf16Encoding(littleEndian))
	if err != nil {
		info.Charset = "UTF-8"
		info.HasBOM = false
		info.UsedSource = "fallback"
		info.Confidence = 0
		return string(raw), info, nil
	}
	return decoded, info, nil
}

// WriteFileWithEncoding converts UTF-8 text back to the original encoding and saves it.
func WriteFileWithEncoding(path string, content string, info EncodingInfo) error {
	// Preserve original file permissions
	perm := os.FileMode(0644)
	if fi, err := os.Stat(path); err == nil {
		perm = fi.Mode().Perm()
	}

	var data []byte

	// UTF-16 first: its HasBOM means a UTF-16 BOM, and falling into the branch
	// below would prepend a UTF-8 BOM to UTF-16 bytes and corrupt the file.
	if info.Charset == "UTF-16LE" || info.Charset == "UTF-16BE" {
		littleEndian := info.Charset == "UTF-16LE"
		encoded, err := encodeString(content, utf16Encoding(littleEndian))
		if err != nil {
			return fmt.Errorf("encoding conversion failed (%s): %w", info.Charset, err)
		}
		if info.HasBOM {
			if littleEndian {
				data = append(append([]byte{}, bomUTF16LE...), encoded...)
			} else {
				data = append(append([]byte{}, bomUTF16BE...), encoded...)
			}
		} else {
			data = encoded
		}
	} else if info.HasBOM {
		data = append(utf8BOM, []byte(content)...)
	} else if info.Charset == "UTF-8" || info.Charset == "" {
		data = []byte(content)
	} else {
		enc, err := ianaindex.IANA.Encoding(info.Charset)
		if err != nil || enc == nil {
			data = []byte(content)
		} else {
			encoded, err := encodeString(content, enc)
			if err != nil {
				return fmt.Errorf("encoding conversion failed (%s): %w", info.Charset, err)
			}
			data = encoded
		}
	}

	// Atomic write: write to temp file first, then rename
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".agent-tool-*.tmp")
	if err != nil {
		// Fall back to direct write if temp file creation fails
		return os.WriteFile(path, data, perm)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Set permissions
	os.Chmod(tmpName, perm)

	// Atomic rename (atomic if on the same filesystem)
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		// Fall back to direct write if rename fails (e.g. cross-drive)
		return os.WriteFile(path, data, perm)
	}
	return nil
}

// DetectLineEnding detects the line ending character in text.
func DetectLineEnding(content string) string {
	if bytes.Contains([]byte(content), []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

// normalizeCharsetName normalizes .editorconfig charset values to IANA names.
func normalizeCharsetName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch lower {
	case "utf-8", "utf8":
		return "UTF-8"
	case "utf-8-bom":
		return "UTF-8" // BOM is handled separately
	case "euc-kr", "euckr":
		return "EUC-KR"
	case "shift_jis", "shift-jis", "shiftjis", "sjis":
		return "Shift_JIS"
	case "latin1", "iso-8859-1":
		return "ISO-8859-1"
	case "utf-16be":
		return "UTF-16BE"
	case "utf-16le":
		return "UTF-16LE"
	default:
		return strings.ToUpper(name)
	}
}

// EncodingWarning returns a warning message when encoding detection confidence is low.
// Returns an empty string if there is no warning.
func EncodingWarning(info EncodingInfo) string {
	if !GetEncodingWarnings() {
		return ""
	}
	if info.UsedSource == "fallback" && info.Confidence == 0 && info.Charset == "UTF-8" {
		return "\n⚠ Encoding detection failed (low confidence). " +
			"If text looks garbled, set --fallback-encoding (e.g. EUC-KR) " +
			"or add 'charset = euc-kr' to .editorconfig."
	}
	if info.UsedSource == "chardet" && info.Confidence < 70 {
		return fmt.Sprintf("\n⚠ Encoding detected as %s (confidence: %d%%). "+
			"If text looks wrong, add 'charset' to .editorconfig for reliable detection.",
			info.Charset, info.Confidence)
	}
	return ""
}

// decodeBytes decodes bytes in the given encoding to a UTF-8 string.
func decodeBytes(raw []byte, enc encoding.Encoding) (string, error) {
	reader := transform.NewReader(bytes.NewReader(raw), enc.NewDecoder())
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// encodeString converts a UTF-8 string to bytes in the given encoding.
func encodeString(s string, enc encoding.Encoding) ([]byte, error) {
	// No conversion needed for UTF-8 family. BOM prefix is handled separately in WriteFileWithEncoding.
	if enc == unicode.UTF8 || enc == unicode.UTF8BOM {
		return []byte(s), nil
	}
	var buf bytes.Buffer
	writer := transform.NewWriter(&buf, enc.NewEncoder())
	_, err := writer.Write([]byte(s))
	if err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ComputeFileHash returns the SHA-256 hash of the file's raw bytes as a hex string.
// Hashes raw bytes without encoding conversion, producing the same result as the checksum tool.
func ComputeFileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
