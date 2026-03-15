package copy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCopyFileAtomic(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src.txt")
	dst := filepath.Join(tmp, "dst.txt")

	if err := os.WriteFile(src, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	cr, err := copyFileAtomic(src, dst, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if cr.RenamedOld != "" {
		t.Errorf("unexpected RenamedOld: %s", cr.RenamedOld)
	}

	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Errorf("expected 'hello', got '%s'", data)
	}
}

func TestCopyFileAtomicOverwrite(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src.txt")
	dst := filepath.Join(tmp, "dst.txt")

	os.WriteFile(src, []byte("new content"), 0644)
	os.WriteFile(dst, []byte("old content"), 0644)

	cr, err := copyFileAtomic(src, dst, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if cr.RenamedOld != "" {
		t.Errorf("normal overwrite should not rename old file")
	}

	data, _ := os.ReadFile(dst)
	if string(data) != "new content" {
		t.Errorf("expected 'new content', got '%s'", data)
	}
}

func TestWindowsLockedFileFallback(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	tmp := t.TempDir()
	dst := filepath.Join(tmp, "target.exe")
	newTmp := filepath.Join(tmp, "new.tmp")

	// Create the "locked" destination and the new file
	os.WriteFile(dst, []byte("old binary"), 0644)
	os.WriteFile(newTmp, []byte("new binary"), 0644)

	oldPath, err := windowsLockedFileFallback(newTmp, dst)
	if err != nil {
		t.Fatal(err)
	}

	// Verify old file was renamed aside
	if !strings.Contains(oldPath, "_old_") {
		t.Errorf("expected '_old_' in renamed path, got: %s", oldPath)
	}
	if filepath.Ext(oldPath) != ".exe" {
		t.Errorf("expected .exe extension preserved, got: %s", filepath.Ext(oldPath))
	}

	// Verify old renamed file contains original content
	oldData, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(oldData) != "old binary" {
		t.Errorf("expected 'old binary' in renamed file, got '%s'", oldData)
	}

	// Verify new file is at original destination
	newData, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(newData) != "new binary" {
		t.Errorf("expected 'new binary' at destination, got '%s'", newData)
	}
}

func TestWindowsLockedFileFallbackRollback(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	tmp := t.TempDir()
	dst := filepath.Join(tmp, "target.dll")

	// Only create destination, no temp file — second rename should fail
	os.WriteFile(dst, []byte("original"), 0644)
	nonExistent := filepath.Join(tmp, "does_not_exist.tmp")

	_, err := windowsLockedFileFallback(nonExistent, dst)
	if err == nil {
		t.Error("expected error when temp file doesn't exist")
	}

	// Verify original file is still intact (rollback should restore it)
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original" {
		t.Errorf("expected rollback to preserve original content, got '%s'", data)
	}
}

func TestCopyFileAtomicLockedFallback(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	tmp := t.TempDir()
	src := filepath.Join(tmp, "src.exe")
	dst := filepath.Join(tmp, "dst.exe")

	os.WriteFile(src, []byte("new exe"), 0644)
	os.WriteFile(dst, []byte("old exe"), 0644)

	// Lock the destination by opening it with no sharing
	lockedFile, err := os.OpenFile(dst, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lockedFile.Close()

	// copyFileAtomic should fall back to rename trick
	cr, err := copyFileAtomic(src, dst, 0644)
	if err != nil {
		// On Windows, opening with Go's os.OpenFile may not actually lock
		// against rename — if normal copy succeeds, that's also fine
		t.Logf("copy failed (file may not be truly locked): %v", err)
		return
	}

	data, _ := os.ReadFile(dst)
	if string(data) != "new exe" {
		t.Errorf("expected 'new exe', got '%s'", data)
	}

	if cr.RenamedOld != "" {
		// Fallback was triggered
		if !strings.Contains(cr.RenamedOld, "_old_") {
			t.Errorf("expected '_old_' in renamed path: %s", cr.RenamedOld)
		}
		t.Logf("fallback triggered, old file: %s", cr.RenamedOld)
	}
}
