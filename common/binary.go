package common

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// binarySniffSize is how many leading bytes IsBinaryFile inspects.
// 8KB matches git's own buffer: large enough to catch a binary header,
// small enough to stay cheap when walking a whole tree.
const binarySniffSize = 8192

// binaryExts lists extensions that are always binary.
//
// Ambiguous extensions (.dat, .img, .bak, .idx, .out) are deliberately NOT
// listed -- the content sniff in IsBinaryFile decides those, so a text file
// carrying such a name stays searchable.
//
// Deliberate omissions:
//   - .svg, .rtf, .pem, .crt, .key: text formats. Skipping them would hide
//     real matches (SVG is XML; read() already returns SVG as text).
//   - .ts: TypeScript far more often than MPEG transport stream.
var binaryExts = map[string]bool{
	// Executables and native build output
	".exe": true, ".dll": true, ".so": true, ".dylib": true,
	".bin": true, ".obj": true, ".o": true, ".a": true,
	".lib": true, ".pdb": true, ".ilk": true, ".exp": true, ".res": true,
	".sys": true, ".ocx": true, ".node": true, ".elf": true, ".ko": true,
	".msi": true, ".cab": true, ".deb": true, ".rpm": true,
	".gch": true, ".pch": true, ".idb": true, ".ipch": true,
	".suo": true, ".vsidx": true, ".wasm": true,

	// Bytecode and language-specific artifacts
	".pyc": true, ".pyo": true, ".pyd": true, ".class": true,
	".jar": true, ".war": true, ".ear": true, ".dex": true,
	".apk": true, ".aab": true, ".rlib": true, ".rmeta": true,
	".beam": true, ".hi": true,

	// Databases and on-disk indexes
	".db": true, ".db-wal": true, ".db-shm": true, ".db-journal": true,
	".sqlite": true, ".sqlite3": true, ".mdb": true, ".accdb": true,
	".realm": true, ".sst": true, ".ldb": true, ".pack": true,

	// Archives and disk images
	".zip": true, ".tar": true, ".gz": true, ".7z": true, ".rar": true,
	".bz2": true, ".xz": true, ".zst": true, ".lz4": true, ".lzma": true,
	".tgz": true, ".tbz2": true, ".txz": true, ".arj": true, ".cpio": true,
	".iso": true, ".dmg": true, ".pkg": true, ".snap": true, ".appimage": true,

	// Images
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".bmp": true, ".ico": true, ".webp": true, ".tiff": true, ".tif": true,
	".heic": true, ".heif": true, ".avif": true, ".jxl": true,
	".psd": true, ".xcf": true, ".dds": true, ".tga": true, ".exr": true,
	".icns": true, ".cr2": true, ".nef": true, ".arw": true,

	// Fonts
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true,
	".eot": true, ".fon": true, ".pfb": true, ".pfm": true,

	// Audio and video
	".mp3": true, ".mp4": true, ".avi": true, ".mov": true,
	".wav": true, ".flac": true, ".aac": true, ".ogg": true, ".oga": true,
	".opus": true, ".m4a": true, ".wma": true, ".aiff": true,
	".mid": true, ".midi": true, ".mkv": true, ".webm": true,
	".wmv": true, ".flv": true, ".mpg": true, ".mpeg": true,
	".m4v": true, ".3gp": true,

	// Documents
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".ppt": true, ".pptx": true, ".odt": true, ".ods": true, ".odp": true,
	".odg": true, ".epub": true, ".mobi": true, ".azw3": true, ".djvu": true,
	".chm": true, ".one": true, ".msg": true, ".pst": true,
	".vsd": true, ".vsdx": true, ".pages": true, ".numbers": true, ".key": true,

	// Model weights and columnar data
	".parquet": true, ".avro": true, ".orc": true, ".feather": true,
	".arrow": true, ".npy": true, ".npz": true, ".pkl": true, ".pickle": true,
	".h5": true, ".hdf5": true, ".mat": true, ".pt": true, ".pth": true,
	".ckpt": true, ".onnx": true, ".tflite": true, ".safetensors": true,
	".gguf": true, ".ggml": true, ".joblib": true,

	// Binary key stores (.pem/.crt/.key are base64 text and stay searchable)
	".pfx": true, ".p12": true, ".der": true, ".jks": true, ".keystore": true,

	".ds_store": true,
}

// IsBinaryExt reports whether a filename has a known-binary extension.
// Pure name check, no I/O -- use it to skip files before opening them.
func IsBinaryExt(name string) bool {
	return binaryExts[strings.ToLower(filepath.Ext(name))]
}

// IsBinaryFile reports whether a file should be skipped by text tools.
//
// Extension check first (no I/O), then a NUL-byte sniff of the leading bytes.
// The content sniff exists because extension lists always lag reality: a
// SQLite index, a compiled blob, or a downloaded artifact under an unlisted
// name would otherwise be decoded and dumped -- one binary "line" can be a
// whole page of garbage, since binaries carry almost no newlines.
//
// Unreadable files return false so the caller's own read reports the real
// error instead of the file silently vanishing from results.
func IsBinaryFile(path string) bool {
	if IsBinaryExt(path) {
		return true
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, binarySniffSize)
	n, err := io.ReadFull(f, buf)
	if n == 0 {
		return false // empty or unreadable: treat as text
	}
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return false
	}
	return isBinaryContent(buf[:n])
}

var (
	bomUTF16LE = []byte{0xFF, 0xFE}
	bomUTF16BE = []byte{0xFE, 0xFF}
	bomUTF32BE = []byte{0x00, 0x00, 0xFE, 0xFF}
)

// isBinaryContent classifies a leading sample as binary or text.
//
// The rule is "contains NUL", with one exception: UTF-16/UTF-32 text is full
// of NUL bytes and must not be misjudged, or this encoding-aware server would
// stop searching the very files it exists to handle. BOM-less UTF-16 is caught
// by parity -- ASCII in UTF-16 puts every NUL on the same odd/even position,
// while a real binary scatters them. The threshold is 80% rather than 100%
// because CJK code points ending in 0x00 (U+AC00 GA, for one) put a NUL on
// the opposite parity, so mixed ASCII/Hangul text never reaches a clean skew.
// The >=4 NUL floor keeps a binary that happens to hold two aligned zero
// bytes from passing the parity test.
func isBinaryContent(sample []byte) bool {
	if bytes.HasPrefix(sample, bomUTF16LE) || bytes.HasPrefix(sample, bomUTF16BE) ||
		bytes.HasPrefix(sample, bomUTF32BE) {
		return false
	}

	nulls, evenNulls := 0, 0
	for i, b := range sample {
		if b != 0 {
			continue
		}
		nulls++
		if i%2 == 0 {
			evenNulls++
		}
	}
	if nulls == 0 {
		return false
	}

	oddNulls := nulls - evenNulls
	skewed := evenNulls
	if oddNulls > skewed {
		skewed = oddNulls
	}
	// 80% on one parity with enough samples to be meaningful -> UTF-16 text.
	if nulls >= 4 && skewed*5 >= nulls*4 {
		return false
	}
	return true
}
