//go:build windows

package wintool

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sys/windows"
)

var (
	procOpenClipboard              = modUser32.NewProc("OpenClipboard")
	procCloseClipboard             = modUser32.NewProc("CloseClipboard")
	procGetClipboardData           = modUser32.NewProc("GetClipboardData")
	procIsClipboardFormatAvailable = modUser32.NewProc("IsClipboardFormatAvailable")
	procCreateWindowExW            = modUser32.NewProc("CreateWindowExW")

	modKernel32      = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalLock   = modKernel32.NewProc("GlobalLock")
	procGlobalUnlock = modKernel32.NewProc("GlobalUnlock")
	procGlobalSize   = modKernel32.NewProc("GlobalSize")
)

const (
	cfDIB       = 8 // CF_DIB clipboard format
	biBitfields = 3 // BI_BITFIELDS compression (channel masks in header)

	openClipboardRetries    = 10
	openClipboardRetryDelay = 100 * time.Millisecond
)

// hwndMessage is HWND_MESSAGE = (HWND)-3 in two's complement, used as a
// parent to create message-only windows that are invisible and never appear
// in the Z-order. Expressed as (^0 - 2) to avoid Go's signed-overflow check
// on uintptr literals.
var hwndMessage = ^uintptr(0) - 2

// ----------------------------------------------------------------------------
// Dedicated clipboard worker
//
// Win32 clipboard APIs (OpenClipboard / CloseClipboard / GetClipboardData /
// GlobalLock / GlobalUnlock) are bound to the calling OS thread. Go goroutines
// can migrate between OS threads at any syscall boundary, so a naive
// "OpenClipboard ... defer CloseClipboard" pattern can end up calling Close
// from a *different* OS thread than the one that opened it -- in which case
// CloseClipboard becomes a no-op and the original thread keeps the clipboard
// locked for the lifetime of the process. This is exactly the "permanently
// stuck clipboard until agent-tool exits" symptom we kept hitting.
//
// Fix: pin all clipboard work to a single dedicated goroutine that calls
// runtime.LockOSThread and never returns. CreateWindowExW for the owner hwnd
// is also done on this thread, so window-thread ownership and clipboard-lock
// ownership are guaranteed to coincide.
// ----------------------------------------------------------------------------

type clipboardJob struct {
	do    func() (*mcp.CallToolResult, WintoolOutput, error)
	reply chan clipboardResult
}

type clipboardResult struct {
	cr  *mcp.CallToolResult
	out WintoolOutput
	err error
}

var (
	clipboardJobs       chan clipboardJob
	clipboardWorkerOnce sync.Once
	clipboardOwnerHWND  uintptr // written only by the worker goroutine
)

// startClipboardWorker spins up the dedicated clipboard goroutine on first
// use. It blocks until the worker has finished CreateWindowExW so callers
// can read clipboardOwnerHWND immediately after this returns.
func startClipboardWorker() {
	clipboardWorkerOnce.Do(func() {
		clipboardJobs = make(chan clipboardJob)
		ready := make(chan struct{})
		go clipboardWorker(ready)
		<-ready
	})
}

func clipboardWorker(ready chan<- struct{}) {
	// Permanently pin this goroutine to its current OS thread. We never call
	// UnlockOSThread -- when this goroutine exits (it never does in practice),
	// Go would terminate the underlying OS thread.
	runtime.LockOSThread()

	clipboardOwnerHWND = createClipboardOwnerHWND()
	close(ready)

	for job := range clipboardJobs {
		runJob(job)
	}
}

// runJob executes one job and ensures a reply is always sent, even on panic,
// so callers never block forever on a worker-side fault.
func runJob(job clipboardJob) {
	defer func() {
		if r := recover(); r != nil {
			job.reply <- clipboardResult{
				err: fmt.Errorf("clipboard worker panic: %v", r),
			}
		}
	}()
	cr, out, err := job.do()
	job.reply <- clipboardResult{cr: cr, out: out, err: err}
}

// runOnClipboardThread dispatches fn to the dedicated clipboard goroutine
// and waits for the result.
func runOnClipboardThread(fn func() (*mcp.CallToolResult, WintoolOutput, error)) (*mcp.CallToolResult, WintoolOutput, error) {
	startClipboardWorker()
	reply := make(chan clipboardResult, 1)
	clipboardJobs <- clipboardJob{do: fn, reply: reply}
	r := <-reply
	return r.cr, r.out, r.err
}

// createClipboardOwnerHWND creates a message-only STATIC window to use as
// the OpenClipboard hwnd argument. Passing NULL there is associated with
// sticky clipboard state in some environments (clipboard owner ends up NULL
// during EmptyClipboard transitions, which causes subsequent SetClipboardData
// calls from other apps to fail). A real message-only hwnd makes us a
// well-behaved clipboard participant -- the same approach used by .NET, Qt,
// and most Win32 clipboard libraries.
//
// MUST be called from the dedicated clipboard worker goroutine. The window's
// owning thread is the caller of CreateWindowExW, and that thread must match
// the thread that subsequently calls OpenClipboard with this hwnd.
//
// The window lives for the lifetime of the process; the OS reclaims it on
// exit. We use the always-registered "STATIC" window class so no
// RegisterClass call is needed.
func createClipboardOwnerHWND() uintptr {
	className, err1 := windows.UTF16PtrFromString("STATIC")
	winName, err2 := windows.UTF16PtrFromString("agent-tool-clipboard")
	if err1 != nil || err2 != nil {
		return 0
	}
	hwnd, _, _ := procCreateWindowExW.Call(
		0, // dwExStyle
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(winName)),
		0,           // dwStyle (not visible, no WS_VISIBLE)
		0, 0, 0, 0,  // x, y, width, height (zero-size)
		hwndMessage, // hWndParent = HWND_MESSAGE -> message-only window
		0,           // hMenu
		0,           // hInstance (NULL = exe module)
		0,           // lpParam
	)
	return hwnd
}

// fullyUnlock calls GlobalUnlock repeatedly until the handle's lock count
// reaches 0. This is necessary for handles returned by GetClipboardData
// because the system may return them with a lock count >= 1 already. A
// single GlobalUnlock would only decrement to >= 1, leaving the handle
// locked from the system's perspective and preventing it from being freed
// on the next EmptyClipboard / SetClipboardData -- which manifests as a
// permanently stuck clipboard until the calling process exits.
//
// GlobalUnlock contract (winbase.h): returns 0 (FALSE) when the lock count
// reaches 0, nonzero when the handle is still locked after the call. The
// upper bound prevents infinite loops if Windows ever returns nonzero
// indefinitely, though that should never happen in practice.
func fullyUnlock(hGlobal uintptr) {
	const maxUnlocks = 32
	for i := 0; i < maxUnlocks; i++ {
		ret, _, _ := procGlobalUnlock.Call(hGlobal)
		if ret == 0 {
			return
		}
	}
}

// openClipboardWithRetry retries OpenClipboard on transient lock contention
// (another process has the clipboard open). 100ms x 10 matches the default
// behavior of .NET Clipboard.SetDataObject. The clipboard is a global
// serialized resource so brief contention is normal and benign.
func openClipboardWithRetry(hwnd uintptr) error {
	var lastErr error
	for i := 0; i < openClipboardRetries; i++ {
		ret, _, err := procOpenClipboard.Call(hwnd)
		if ret != 0 {
			return nil
		}
		lastErr = err
		if i < openClipboardRetries-1 {
			time.Sleep(openClipboardRetryDelay)
		}
	}
	return fmt.Errorf("OpenClipboard failed after %d retries (clipboard locked by another process): %v", openClipboardRetries, lastErr)
}

// opClipboard is the public entry point. It dispatches the actual work to the
// pinned clipboard worker goroutine; see the worker block above for why.
func opClipboard(input WintoolInput) (*CallResult, WintoolOutput, error) {
	return runOnClipboardThread(func() (*CallResult, WintoolOutput, error) {
		return opClipboardOnWorker(input)
	})
}

// opClipboardOnWorker reads an image from the Windows clipboard.
// Default: returns base64 PNG via MCP ImageContent.
// If save_path is set: saves PNG to that path and returns the path.
// Reuses bitmapInfoHeader from screenshot_windows.go (same package).
//
// MUST run on the dedicated clipboard worker goroutine -- all Win32 clipboard
// calls below are bound to the caller OS thread.
func opClipboardOnWorker(input WintoolInput) (*CallResult, WintoolOutput, error) {
	// Check if clipboard has a bitmap
	avail, _, _ := procIsClipboardFormatAvailable.Call(cfDIB)
	if avail == 0 {
		return errorResult("no image in clipboard. Copy an image or take a screenshot (Win+Shift+S) first")
	}

	hwnd := clipboardOwnerHWND
	if hwnd == 0 {
		return errorResult("clipboard owner window not initialized (CreateWindowExW failed at startup)")
	}

	// CRITICAL: keep the clipboard locked for the shortest possible window.
	// Holding it through PNG encoding/file write blocks every other process
	// that wants OpenClipboard. We unlock+close right after pixel copy.
	if openErr := openClipboardWithRetry(hwnd); openErr != nil {
		return errorResult("%v", openErr)
	}
	clipboardOpen := true
	defer func() {
		if clipboardOpen {
			procCloseClipboard.Call()
		}
	}()

	// GetClipboardData(CF_DIB) returns HGLOBAL to a packed DIB
	hGlobal, _, err := procGetClipboardData.Call(cfDIB)
	if hGlobal == 0 {
		return errorResult("GetClipboardData(CF_DIB) failed: %v", err)
	}

	ptr, _, err := procGlobalLock.Call(hGlobal)
	if ptr == 0 {
		return errorResult("GlobalLock failed: %v", err)
	}
	locked := true
	// CRITICAL: GetClipboardData returns a system-cached / synthesized handle
	// whose lock count may already be >= 1 before we call GlobalLock. A single
	// GlobalUnlock then leaves lock count >= 1, which prevents the system
	// from freeing the handle on the next EmptyClipboard / SetClipboardData
	// -- the symptom is "clipboard permanently stuck after wintool clipboard
	// read until the agent-tool process is killed". We must keep calling
	// GlobalUnlock until it returns 0 (lock count reached 0 / already 0).
	defer func() {
		if locked {
			fullyUnlock(hGlobal)
		}
	}()

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

	// Release clipboard ASAP -- PNG encode and file write below no longer
	// need the source DIB. fullyUnlock drains the lock count to 0 (see the
	// note above: a single GlobalUnlock can leave a system-cached handle
	// locked, which permanently breaks the clipboard for other apps).
	fullyUnlock(hGlobal)
	locked = false
	procCloseClipboard.Call()
	clipboardOpen = false

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
