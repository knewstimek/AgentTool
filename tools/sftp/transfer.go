package sftp

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"agent-tool/common"
	"agent-tool/tools/ssh"

	gosftp "github.com/pkg/sftp"
)

const (
	// maxConcurrentTransfers limits simultaneous async transfers.
	maxConcurrentTransfers = 10

	// transferCleanupAge is how long completed transfers stay in the map.
	transferCleanupAge = 1 * time.Hour

	// transferCleanupInterval is how often we check for expired transfers.
	transferCleanupInterval = 5 * time.Minute
)

// transferEntry tracks a background file transfer.
type transferEntry struct {
	ID          string
	Operation   string // "upload" or "download"
	LocalPath   string
	RemotePath  string
	TotalSize   int64
	Transferred atomic.Int64
	Status      string // "running", "completed", "failed", "cancelled"
	Error       string
	StartedAt   time.Time
	CompletedAt time.Time
	cancel      context.CancelFunc
	mu          sync.Mutex
}

var transfers = struct {
	mu sync.Mutex
	m  map[string]*transferEntry
}{m: make(map[string]*transferEntry)}

func init() {
	go transferReaper()
}

// transferReaper periodically removes completed/failed/cancelled transfers older than transferCleanupAge.
func transferReaper() {
	ticker := time.NewTicker(transferCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		transfers.mu.Lock()
		for id, e := range transfers.m {
			e.mu.Lock()
			if e.Status != "running" && now.Sub(e.CompletedAt) > transferCleanupAge {
				delete(transfers.m, id)
			}
			e.mu.Unlock()
		}
		transfers.mu.Unlock()
	}
}

// generateID creates a short random transfer ID using crypto/rand.
func generateID() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	randomBytes := make([]byte, 12)
	if _, err := rand.Read(randomBytes); err != nil {
		// crypto/rand failure is a system-level issue
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	b := make([]byte, 12)
	for i := range b {
		b[i] = chars[randomBytes[i]%byte(len(chars))]
	}
	return string(b)
}

// allocateTransferID checks the concurrent limit, generates a unique ID, and inserts
// the entry atomically. Returns the ID or an error if the limit is reached.
// Caller must hold NO locks.
func allocateTransferID(entry *transferEntry) (string, error) {
	transfers.mu.Lock()
	defer transfers.mu.Unlock()

	// Atomic check-and-insert: count + allocate in same critical section
	running := 0
	for _, e := range transfers.m {
		e.mu.Lock()
		if e.Status == "running" {
			running++
		}
		e.mu.Unlock()
	}
	if running >= maxConcurrentTransfers {
		return "", fmt.Errorf("too many concurrent transfers (max %d)", maxConcurrentTransfers)
	}

	id := generateID()
	for transfers.m[id] != nil {
		id = generateID()
	}
	entry.ID = id
	transfers.m[id] = entry
	return id, nil
}

// progressReader wraps an io.Reader and tracks bytes read.
type progressReader struct {
	reader io.Reader
	count  *atomic.Int64
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	if n > 0 {
		pr.count.Add(int64(n))
	}
	return n, err
}

// progressWriter wraps an io.Writer and tracks bytes written.
type progressWriter struct {
	writer io.Writer
	count  *atomic.Int64
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.writer.Write(p)
	if n > 0 {
		pw.count.Add(int64(n))
	}
	return n, err
}

// startAsyncUpload starts a background upload and returns the transfer ID.
func startAsyncUpload(input SFTPInput) (string, error) {
	if err := validateLocalPath(input.LocalPath); err != nil {
		return "", err
	}
	if err := validateRemotePath(input.RemotePath); err != nil {
		return "", err
	}

	// Pre-check local file
	localInfo, err := os.Stat(input.LocalPath)
	if err != nil {
		return "", fmt.Errorf("local file: %w", err)
	}
	if localInfo.IsDir() {
		return "", fmt.Errorf("local_path is a directory, not a file")
	}
	if localInfo.Size() > maxTransferSize {
		return "", fmt.Errorf("file too large: %s (max %s)", formatSize(localInfo.Size()), formatSize(maxTransferSize))
	}

	ctx, cancel := context.WithCancel(context.Background())

	entry := &transferEntry{
		Operation:  "upload",
		LocalPath:  input.LocalPath,
		RemotePath: input.RemotePath,
		TotalSize:  localInfo.Size(),
		Status:     "running",
		StartedAt:  time.Now(),
		cancel:     cancel,
	}

	// Atomic: check concurrent limit + allocate ID + insert entry
	id, err := allocateTransferID(entry)
	if err != nil {
		cancel()
		return "", err
	}
	go runAsyncUpload(ctx, entry, input)

	return id, nil
}

// startAsyncDownload starts a background download and returns the transfer ID.
func startAsyncDownload(input SFTPInput) (string, error) {
	if err := validateRemotePath(input.RemotePath); err != nil {
		return "", err
	}
	if err := validateLocalPath(input.LocalPath); err != nil {
		return "", err
	}
	if err := isSensitiveLocalPath(input.LocalPath); err != nil {
		return "", err
	}

	// We need to check remote file size, which requires SSH connection
	sshInput := toSSHInput(input)
	sshClient, _, err := ssh.GetClient(sshInput)
	if err != nil {
		return "", fmt.Errorf("SSH connection failed: %s", ssh.SanitizeError(err, sshInput))
	}

	sftpClient, err := gosftp.NewClient(sshClient)
	if err != nil {
		if isConnectionBroken(err) {
			ssh.RemoveClient(input.Host, input.Port, input.User)
		}
		return "", fmt.Errorf("SFTP subsystem failed: %v", err)
	}

	remoteInfo, err := sftpClient.Stat(input.RemotePath)
	sftpClient.Close()
	if err != nil {
		return "", fmt.Errorf("remote file: %v", err)
	}
	if remoteInfo.IsDir() {
		return "", fmt.Errorf("remote_path is a directory, not a file")
	}
	if remoteInfo.Size() > maxTransferSize {
		return "", fmt.Errorf("file too large: %s (max %s)", formatSize(remoteInfo.Size()), formatSize(maxTransferSize))
	}

	ssh.TouchClient(input.Host, input.Port, input.User)

	ctx, cancel := context.WithCancel(context.Background())

	entry := &transferEntry{
		Operation:  "download",
		LocalPath:  input.LocalPath,
		RemotePath: input.RemotePath,
		TotalSize:  remoteInfo.Size(),
		Status:     "running",
		StartedAt:  time.Now(),
		cancel:     cancel,
	}

	// Atomic: check concurrent limit + allocate ID + insert entry
	id, err := allocateTransferID(entry)
	if err != nil {
		cancel()
		return "", err
	}
	go runAsyncDownload(ctx, entry, input)

	return id, nil
}

// runAsyncUpload performs the actual upload in a background goroutine.
func runAsyncUpload(ctx context.Context, entry *transferEntry, input SFTPInput) {
	defer entry.cancel()

	sshInput := toSSHInput(input)
	sshClient, _, err := ssh.GetClient(sshInput)
	if err != nil {
		entry.mu.Lock()
		entry.Status = "failed"
		// Sanitize error to prevent password leakage in stored error messages
		entry.Error = fmt.Sprintf("SSH connection: %s", ssh.SanitizeError(err, sshInput))
		entry.CompletedAt = time.Now()
		entry.mu.Unlock()
		return
	}

	sftpClient, err := gosftp.NewClient(sshClient)
	if err != nil {
		if isConnectionBroken(err) {
			ssh.RemoveClient(input.Host, input.Port, input.User)
		}
		entry.mu.Lock()
		entry.Status = "failed"
		entry.Error = fmt.Sprintf("SFTP: %v", err)
		entry.CompletedAt = time.Now()
		entry.mu.Unlock()
		return
	}
	defer sftpClient.Close()

	// Check overwrite
	if !common.FlexBool(input.Overwrite) {
		if _, err := sftpClient.Stat(input.RemotePath); err == nil {
			entry.mu.Lock()
			entry.Status = "failed"
			entry.Error = fmt.Sprintf("remote file already exists: %s", input.RemotePath)
			entry.CompletedAt = time.Now()
			entry.mu.Unlock()
			return
		}
	}

	localFile, err := os.Open(input.LocalPath)
	if err != nil {
		entry.mu.Lock()
		entry.Status = "failed"
		entry.Error = fmt.Sprintf("open local file: %v", err)
		entry.CompletedAt = time.Now()
		entry.mu.Unlock()
		return
	}
	defer localFile.Close()

	remoteFile, err := sftpClient.Create(input.RemotePath)
	if err != nil {
		entry.mu.Lock()
		entry.Status = "failed"
		entry.Error = fmt.Sprintf("create remote file: %v", err)
		entry.CompletedAt = time.Now()
		entry.mu.Unlock()
		return
	}
	defer remoteFile.Close()

	// Copy with progress tracking and cancellation
	pr := &progressReader{reader: localFile, count: &entry.Transferred}
	_, err = copyWithCancel(ctx, remoteFile, pr)

	entry.mu.Lock()
	defer entry.mu.Unlock()
	entry.CompletedAt = time.Now()

	if ctx.Err() != nil {
		entry.Status = "cancelled"
		entry.Error = "transfer cancelled by user"
		sftpClient.Remove(input.RemotePath) // clean up partial remote file
	} else if err != nil {
		entry.Status = "failed"
		entry.Error = fmt.Sprintf("upload: %v", err)
		sftpClient.Remove(input.RemotePath) // clean up partial remote file
	} else {
		entry.Status = "completed"
	}

	ssh.TouchClient(input.Host, input.Port, input.User)
}

// runAsyncDownload performs the actual download in a background goroutine.
func runAsyncDownload(ctx context.Context, entry *transferEntry, input SFTPInput) {
	defer entry.cancel()

	sshInput := toSSHInput(input)
	sshClient, _, err := ssh.GetClient(sshInput)
	if err != nil {
		entry.mu.Lock()
		entry.Status = "failed"
		// Sanitize error to prevent password leakage in stored error messages
		entry.Error = fmt.Sprintf("SSH connection: %s", ssh.SanitizeError(err, sshInput))
		entry.CompletedAt = time.Now()
		entry.mu.Unlock()
		return
	}

	sftpClient, err := gosftp.NewClient(sshClient)
	if err != nil {
		if isConnectionBroken(err) {
			ssh.RemoveClient(input.Host, input.Port, input.User)
		}
		entry.mu.Lock()
		entry.Status = "failed"
		entry.Error = fmt.Sprintf("SFTP: %v", err)
		entry.CompletedAt = time.Now()
		entry.mu.Unlock()
		return
	}
	defer sftpClient.Close()

	// Check overwrite
	if !common.FlexBool(input.Overwrite) {
		if _, err := os.Stat(input.LocalPath); err == nil {
			entry.mu.Lock()
			entry.Status = "failed"
			entry.Error = fmt.Sprintf("local file already exists: %s", input.LocalPath)
			entry.CompletedAt = time.Now()
			entry.mu.Unlock()
			return
		}
	}

	// Create local directory
	localDir := filepath.Dir(input.LocalPath)
	if err := os.MkdirAll(localDir, 0755); err != nil {
		entry.mu.Lock()
		entry.Status = "failed"
		entry.Error = fmt.Sprintf("create directory: %v", err)
		entry.CompletedAt = time.Now()
		entry.mu.Unlock()
		return
	}

	remoteFile, err := sftpClient.Open(input.RemotePath)
	if err != nil {
		entry.mu.Lock()
		entry.Status = "failed"
		entry.Error = fmt.Sprintf("open remote file: %v", err)
		entry.CompletedAt = time.Now()
		entry.mu.Unlock()
		return
	}
	defer remoteFile.Close()

	localFile, err := os.Create(input.LocalPath)
	if err != nil {
		entry.mu.Lock()
		entry.Status = "failed"
		entry.Error = fmt.Sprintf("create local file: %v", err)
		entry.CompletedAt = time.Now()
		entry.mu.Unlock()
		return
	}

	// Copy with progress tracking and cancellation
	pw := &progressWriter{writer: localFile, count: &entry.Transferred}
	_, err = copyWithCancel(ctx, pw, remoteFile)
	closeErr := localFile.Close()

	entry.mu.Lock()
	defer entry.mu.Unlock()
	entry.CompletedAt = time.Now()

	if ctx.Err() != nil {
		entry.Status = "cancelled"
		entry.Error = "transfer cancelled by user"
		os.Remove(input.LocalPath) // clean up partial
	} else if err != nil {
		entry.Status = "failed"
		entry.Error = fmt.Sprintf("download: %v", err)
		os.Remove(input.LocalPath) // clean up partial
	} else if closeErr != nil {
		entry.Status = "failed"
		entry.Error = fmt.Sprintf("close local file: %v", closeErr)
		os.Remove(input.LocalPath) // clean up incomplete
	} else {
		entry.Status = "completed"
	}

	ssh.TouchClient(input.Host, input.Port, input.User)
}

// copyWithCancel copies from src to dst, checking for context cancellation periodically.
func copyWithCancel(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 32*1024) // 32KB buffer
	var total int64

	for {
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}

		n, readErr := src.Read(buf)
		if n > 0 {
			nw, writeErr := dst.Write(buf[:n])
			total += int64(nw)
			if writeErr != nil {
				return total, writeErr
			}
			if nw < n {
				return total, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return total, nil
			}
			return total, readErr
		}
	}
}

// opStatus returns the status of a transfer or all active transfers.
func opStatus(input SFTPInput) (string, error) {
	transferID := input.TransferID

	if transferID != "" {
		// Single transfer status
		transfers.mu.Lock()
		entry, ok := transfers.m[transferID]
		transfers.mu.Unlock()

		if !ok {
			return "", fmt.Errorf("transfer not found: %s", transferID)
		}

		return formatTransferStatus(entry), nil
	}

	// All transfers
	transfers.mu.Lock()
	entries := make([]*transferEntry, 0, len(transfers.m))
	for _, e := range transfers.m {
		entries = append(entries, e)
	}
	transfers.mu.Unlock()

	if len(entries) == 0 {
		return "No active or recent transfers.", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Transfers (%d) ===\n\n", len(entries)))
	for _, e := range entries {
		sb.WriteString(formatTransferStatus(e))
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

// opCancel cancels a running transfer.
func opCancel(input SFTPInput) (string, error) {
	if input.TransferID == "" {
		return "", fmt.Errorf("transfer_id is required for cancel")
	}

	transfers.mu.Lock()
	entry, ok := transfers.m[input.TransferID]
	transfers.mu.Unlock()

	if !ok {
		return "", fmt.Errorf("transfer not found: %s", input.TransferID)
	}

	entry.mu.Lock()
	status := entry.Status
	entry.mu.Unlock()

	if status != "running" {
		return fmt.Sprintf("Transfer %s is already %s", input.TransferID, status), nil
	}

	entry.cancel()
	return fmt.Sprintf("Cancel requested for transfer %s", input.TransferID), nil
}

// formatTransferStatus formats a single transfer entry for display.
func formatTransferStatus(e *transferEntry) string {
	e.mu.Lock()
	defer e.mu.Unlock()

	transferred := e.Transferred.Load()
	var progress string
	if e.TotalSize > 0 {
		pct := float64(transferred) / float64(e.TotalSize) * 100
		progress = fmt.Sprintf("%s / %s (%.1f%%)", formatSize(transferred), formatSize(e.TotalSize), pct)
	} else {
		progress = formatSize(transferred)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ID: %s\n", e.ID))
	sb.WriteString(fmt.Sprintf("Operation: %s\n", e.Operation))
	sb.WriteString(fmt.Sprintf("Local: %s\n", e.LocalPath))
	sb.WriteString(fmt.Sprintf("Remote: %s\n", e.RemotePath))
	sb.WriteString(fmt.Sprintf("Progress: %s\n", progress))
	sb.WriteString(fmt.Sprintf("Status: %s\n", e.Status))

	if e.Error != "" {
		sb.WriteString(fmt.Sprintf("Error: %s\n", e.Error))
	}

	elapsed := time.Since(e.StartedAt)
	if e.Status == "running" {
		sb.WriteString(fmt.Sprintf("Elapsed: %s\n", elapsed.Round(time.Second)))
		if transferred > 0 && elapsed.Seconds() > 0 {
			speed := float64(transferred) / elapsed.Seconds()
			sb.WriteString(fmt.Sprintf("Speed: %s/s\n", formatSize(int64(speed))))
			if e.TotalSize > transferred {
				remaining := float64(e.TotalSize-transferred) / speed
				sb.WriteString(fmt.Sprintf("ETA: %s\n", time.Duration(remaining*float64(time.Second)).Round(time.Second)))
			}
		}
	} else {
		duration := e.CompletedAt.Sub(e.StartedAt)
		sb.WriteString(fmt.Sprintf("Duration: %s\n", duration.Round(time.Second)))
	}

	return sb.String()
}
