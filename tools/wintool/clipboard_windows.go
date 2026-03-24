//go:build windows

package wintool

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"os"
	"unsafe"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sys/windows"
)

var (
	procOpenClipboard              = modUser32.NewProc("OpenClipboard")
	procCloseClipboard             = modUser32.NewProc("CloseClipboard")
	procGetClipboardData           = modUser32.NewProc("GetClipboardData")
	procIsClipboardFormatAvailable = modUser32.NewProc("IsClipboardFormatAvailable")

	modKernel32      = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalLock   = modKernel32.NewProc("GlobalLock")
	procGlobalUnlock = modKernel32.NewProc("GlobalUnlock")
	procGlobalSize   = modKernel32.NewProc("GlobalSize")
)

const (
	cfDIB       = 8 // CF_DIB clipboard format
	biBitfields = 3 // BI_BITFIELDS compression (channel masks in header)
)

// opClipboard reads an image from the Windows clipboard.
// Default: returns base64 PNG via MCP ImageContent.
// If save_path is set: saves PNG to that path and returns the path.
// Reuses bitmapInfoHeader from screenshot_windows.go (same package).
func opClipboard(input WintoolInput) (*CallResult, WintoolOutput, error) {
	// Check if clipboard has a bitmap
	avail, _, _ := procIsClipboardFormatAvailable.Call(cfDIB)
	if avail == 0 {
		return errorResult("no image in clipboard. Copy an image or take a screenshot (Win+Shift+S) first")
	}

	// OpenClipboard(NULL) - associate with current task
	ret, _, err := procOpenClipboard.Call(0)
	if ret == 0 {
		return errorResult("OpenClipboard failed: %v", err)
	}
	defer procCloseClipboard.Call()

	// GetClipboardData(CF_DIB) returns HGLOBAL to a packed DIB
	hGlobal, _, err := procGetClipboardData.Call(cfDIB)
	if hGlobal == 0 {
		return errorResult("GetClipboardData(CF_DIB) failed: %v", err)
	}

	ptr, _, err := procGlobalLock.Call(hGlobal)
	if ptr == 0 {
		return errorResult("GlobalLock failed: %v", err)
	}
	defer procGlobalUnlock.Call(hGlobal)

	globalSize, _, _ := procGlobalSize.Call(hGlobal)
	if globalSize < unsafe.Sizeof(bitmapInfoHeader{}) {
		return errorResult("clipboard DIB too small (%d bytes)", globalSize)
	}

	// Parse BITMAPINFOHEADER at the start of the DIB data
	hdr := (*bitmapInfoHeader)(unsafe.Pointer(ptr))

	w := int(hdr.Width)
	h := int(hdr.Height)
	topDown := false
	if h < 0 {
		h = -h
		topDown = true
	}

	if w <= 0 || h <= 0 {
		return errorResult("invalid DIB dimensions: %dx%d", w, h)
	}
	if w > maxScreenshotWidth || h > maxScreenshotHeight {
		return errorResult("clipboard image too large (%dx%d, max %dx%d)", w, h, maxScreenshotWidth, maxScreenshotHeight)
	}
	if hdr.BitCount != 32 && hdr.BitCount != 24 {
		return errorResult("unsupported bit depth %d (expected 24 or 32)", hdr.BitCount)
	}
	if hdr.Compression != biRGB && !(hdr.Compression == biBitfields && hdr.BitCount == 32) {
		return errorResult("unsupported compression %d (expected BI_RGB=0 or BI_BITFIELDS=3 with 32bpp)", hdr.Compression)
	}

	// Validate header size (BITMAPINFOHEADER=40, V4=108, V5=124).
	// Reject abnormal values to prevent pixelOffset manipulation.
	if hdr.Size < 40 || hdr.Size > 1024 {
		return errorResult("invalid DIB header size %d (expected 40-124)", hdr.Size)
	}
	pixelOffset := uintptr(hdr.Size)
	// BI_BITFIELDS has 3 DWORD channel masks after the header (when header is plain BITMAPINFOHEADER)
	if hdr.Compression == biBitfields && hdr.Size == 40 {
		pixelOffset += 12
	}

	bytesPerPixel := int(hdr.BitCount) / 8
	// Rows are padded to 4-byte boundary
	stride := ((w*bytesPerPixel + 3) / 4) * 4
	expectedSize := uintptr(stride * h)

	// Overflow-safe bounds check: use subtraction to prevent uintptr wrap-around bypass
	pixelPtr := ptr + pixelOffset
	if pixelOffset > uintptr(globalSize) || expectedSize > uintptr(globalSize)-pixelOffset {
		return errorResult("DIB pixel data exceeds buffer (offset=%d, need=%d, have=%d)", pixelOffset, expectedSize, globalSize)
	}

	pixels := unsafe.Slice((*byte)(unsafe.Pointer(pixelPtr)), int(expectedSize))

	// Convert to RGBA image
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		srcY := y
		if !topDown {
			// Bottom-up DIB: flip vertically
			srcY = h - 1 - y
		}
		srcRow := srcY * stride
		dstRow := y * w * 4

		if bytesPerPixel == 4 {
			// BGRA -> RGBA
			for x := 0; x < w; x++ {
				si := srcRow + x*4
				di := dstRow + x*4
				img.Pix[di+0] = pixels[si+2] // R <- B
				img.Pix[di+1] = pixels[si+1] // G
				img.Pix[di+2] = pixels[si+0] // B <- R
				img.Pix[di+3] = 255          // A (opaque)
			}
		} else {
			// 24-bit BGR -> RGBA
			for x := 0; x < w; x++ {
				si := srcRow + x*3
				di := dstRow + x*4
				img.Pix[di+0] = pixels[si+2] // R <- B
				img.Pix[di+1] = pixels[si+1] // G
				img.Pix[di+2] = pixels[si+0] // B <- R
				img.Pix[di+3] = 255          // A
			}
		}
	}

	// Encode PNG to buffer
	var buf bytes.Buffer
	if encErr := png.Encode(&buf, img); encErr != nil {
		return errorResult("PNG encode failed: %v", encErr)
	}
	pngData := buf.Bytes()

	// save_path: "temp" -> auto temp file, absolute path -> that path, empty -> ImageContent
	if input.SavePath != "" {
		saveTo, sErr := resolveSavePath(input.SavePath, "wintool-clipboard-*.png")
		if sErr != nil {
			return errorResult("%v", sErr)
		}
		if wErr := os.WriteFile(saveTo, pngData, 0644); wErr != nil {
			return errorResult("failed to write file: %v", wErr)
		}
		msg := fmt.Sprintf("Clipboard image saved: %s (%dx%d, %d bytes)", saveTo, w, h, len(pngData))
		return successResult(msg)
	}

	// Default: return as MCP ImageContent (base64)
	msg := fmt.Sprintf("Clipboard image: %dx%d (%d bytes PNG)", w, h, len(pngData))
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.ImageContent{Data: pngData, MIMEType: "image/png"},
			&mcp.TextContent{Text: msg},
		},
	}, WintoolOutput{Result: msg}, nil
}
