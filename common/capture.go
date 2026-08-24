package common

import (
	"bytes"
	"fmt"
	"sync"
)

// BoundedCapture consumes an unlimited byte stream while retaining a bounded,
// representative head and tail. It always reports the original byte count so
// callers can make truncation visible instead of silently discarding output.
type BoundedCapture struct {
	mu    sync.Mutex
	limit int
	mode  string
	total int64
	head  []byte
	tail  []byte
}

func NewBoundedCapture(limit int) *BoundedCapture {
	return NewBoundedCaptureMode(limit, "head_tail")
}

func NewBoundedCaptureMode(limit int, mode string) *BoundedCapture {
	if limit < 0 {
		limit = 0
	}
	if mode != "head" && mode != "tail" {
		mode = "head_tail"
	}
	return &BoundedCapture{limit: limit, mode: mode}
}

func (c *BoundedCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	originalLen := len(p)
	c.total += int64(originalLen)
	if c.limit == 0 {
		return originalLen, nil
	}
	headLimit, tailLimit := (c.limit+1)/2, c.limit/2
	if c.mode == "head" {
		headLimit, tailLimit = c.limit, 0
	} else if c.mode == "tail" {
		headLimit, tailLimit = 0, c.limit
	}
	if len(c.head) < headLimit {
		n := headLimit - len(c.head)
		if n > len(p) {
			n = len(p)
		}
		c.head = append(c.head, p[:n]...)
		p = p[n:]
	}
	if tailLimit > 0 && len(p) > 0 {
		c.tail = append(c.tail, p...)
		if len(c.tail) > tailLimit {
			c.tail = append([]byte(nil), c.tail[len(c.tail)-tailLimit:]...)
		}
	}
	return originalLen, nil
}

// Result returns valid UTF-8 output plus truncation metadata. Invalid or split
// byte sequences are replaced rather than leaking malformed text to MCP JSON.
func (c *BoundedCapture) Result() (text string, totalBytes int64, truncated bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	totalBytes = c.total
	truncated = totalBytes > int64(c.limit)
	if !truncated {
		combined := append(append([]byte(nil), c.head...), c.tail...)
		return string(bytes.ToValidUTF8(combined, []byte("\uFFFD"))), totalBytes, false
	}
	marker := []byte(fmt.Sprintf("\n...[truncated; original_bytes=%d; retained_bytes=%d]...\n", totalBytes, c.limit))
	combined := make([]byte, 0, len(c.head)+len(marker)+len(c.tail))
	combined = append(combined, bytes.ToValidUTF8(c.head, []byte("\uFFFD"))...)
	combined = append(combined, marker...)
	combined = append(combined, bytes.ToValidUTF8(c.tail, []byte("\uFFFD"))...)
	return string(bytes.ToValidUTF8(combined, []byte("\uFFFD"))), totalBytes, true
}
