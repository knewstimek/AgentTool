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
	modGdi32 = windows.NewLazySystemDLL("gdi32.dll")

	procGetDC              = modUser32.NewProc("GetDC")
	procReleaseDC          = modUser32.NewProc("ReleaseDC")
	procPrintWindow        = modUser32.NewProc("PrintWindow")
	procCreateCompatibleDC = modGdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSection   = modGdi32.NewProc("CreateDIBSection")
	procSelectObject       = modGdi32.NewProc("SelectObject")
	procDeleteObject       = modGdi32.NewProc("DeleteObject")
	procDeleteDC           = modGdi32.NewProc("DeleteDC")
	procBitBlt             = modGdi32.NewProc("BitBlt")
)

const (
	biRGB              = 0
	dibRGBColors       = 0
	srcCopy            = 0x00CC0020
	pwRenderFullContent = 0x00000002 // PW_RENDERFULLCONTENT (Win8.1+)
	pwClientOnly        = 0x00000001 // PW_CLIENTONLY

	// Screenshot size limits to prevent excessive memory/base64 output
	maxScreenshotWidth  = 4096
	maxScreenshotHeight = 4096
)

// BITMAPINFOHEADER for GetDIBits.
type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

// BITMAPINFO for GetDIBits (no color table for 32-bit).
type bitmapInfo struct {
	Header bitmapInfoHeader
}

// opScreenshot captures a window and returns base64-encoded PNG.
// Uses CreateDIBSection instead of GetDIBits — the DIB section gives us a direct
// pointer to the pixel buffer, avoiding GetDIBits compatibility issues on 64-bit.
func opScreenshot(input WintoolInput) (*CallResult, WintoolOutput, error) {
	hwnd, errResult, errOutput := requireHWND(input)
	if errResult != nil {
		return errResult, errOutput, nil
	}
	if !isWindow(hwnd) {
		return errorResult("hwnd 0x%X is not a valid window", hwnd)
	}

	cr := getClientRect(hwnd)
	w := int(cr.Right)
	h := int(cr.Bottom)
	if w <= 0 || h <= 0 {
		return errorResult("window has zero client area (%dx%d)", w, h)
	}
	if w > maxScreenshotWidth || h > maxScreenshotHeight {
		return errorResult("window too large for screenshot (%dx%d, max %dx%d)", w, h, maxScreenshotWidth, maxScreenshotHeight)
	}

	hdcScreen, _, _ := procGetDC.Call(0)
	if hdcScreen == 0 {
		return errorResult("GetDC(screen) failed")
	}
	defer procReleaseDC.Call(0, hdcScreen)

	hdcMem, _, _ := procCreateCompatibleDC.Call(hdcScreen)
	if hdcMem == 0 {
		return errorResult("CreateCompatibleDC failed")
	}
	defer procDeleteDC.Call(hdcMem)

	// Use CreateDIBSection to get a bitmap with a direct pointer to pixel data.
	// Negative height = top-down DIB (no vertical flip needed).
	bi := bitmapInfo{
		Header: bitmapInfoHeader{
			Size:        uint32(unsafe.Sizeof(bitmapInfoHeader{})),
			Width:       int32(w),
			Height:      -int32(h), // negative = top-down
			Planes:      1,
			BitCount:    32,
			Compression: biRGB,
		},
	}

	var ppvBits uintptr // receives pointer to pixel data
	hBmp, _, lastErr := procCreateDIBSection.Call(
		hdcScreen,
		uintptr(unsafe.Pointer(&bi)),
		dibRGBColors,
		uintptr(unsafe.Pointer(&ppvBits)),
		0, 0)
	if hBmp == 0 {
		return errorResult("CreateDIBSection failed: %v", lastErr)
	}
	defer procDeleteObject.Call(hBmp)

	oldBmp, _, _ := procSelectObject.Call(hdcMem, hBmp)

	// Try PrintWindow first (captures even if window is occluded)
	ret, _, _ := procPrintWindow.Call(hwnd, hdcMem, pwRenderFullContent|pwClientOnly)
	if ret == 0 {
		// Fallback to BitBlt (only captures visible portion)
		hdcWin, _, _ := procGetDC.Call(hwnd)
		if hdcWin != 0 {
			ret, _, _ = procBitBlt.Call(hdcMem, 0, 0, uintptr(w), uintptr(h),
				hdcWin, 0, 0, srcCopy)
			procReleaseDC.Call(hwnd, hdcWin)
		}
		if ret == 0 {
			return errorResult("both PrintWindow and BitBlt failed for hwnd 0x%X", hwnd)
		}
	}

	// Restore original bitmap before reading pixels
	procSelectObject.Call(hdcMem, oldBmp)

	// ppvBits points directly to BGRA pixel data (top-down, no flip needed).
	totalBytes := w * h * 4
	pixels := unsafe.Slice((*byte)(unsafe.Pointer(ppvBits)), totalBytes)

	// Convert BGRA → RGBA
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < totalBytes; i += 4 {
		img.Pix[i+0] = pixels[i+2] // R ← B
		img.Pix[i+1] = pixels[i+1] // G
		img.Pix[i+2] = pixels[i+0] // B ← R
		img.Pix[i+3] = 255         // A (opaque)
	}

	// Encode PNG to buffer
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return errorResult("PNG encode failed: %v", err)
	}
	pngData := buf.Bytes()

	// save_path: "temp" -> auto temp file, absolute path -> that path, empty -> ImageContent
	if input.SavePath != "" {
		saveTo, sErr := resolveSavePath(input.SavePath, "wintool-screenshot-*.png")
		if sErr != nil {
			return errorResult("%v", sErr)
		}
		if ferr := os.WriteFile(saveTo, pngData, 0644); ferr != nil {
			return errorResult("failed to write file: %v", ferr)
		}
		msg := fmt.Sprintf("Screenshot saved: %s (%dx%d, %d bytes)", saveTo, w, h, len(pngData))
		return successResult(msg)
	}

	// Default: return as MCP ImageContent (base64)
	msg := fmt.Sprintf("Screenshot: %dx%d (%d bytes PNG)", w, h, len(pngData))
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.ImageContent{Data: pngData, MIMEType: "image/png"},
			&mcp.TextContent{Text: msg},
		},
	}, WintoolOutput{Result: msg}, nil
}
