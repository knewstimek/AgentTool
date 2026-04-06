package sftp

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"agent-tool/common"

	"github.com/pkg/sftp"
)

// opUpload transfers a local file to the remote server.
func opUpload(client *sftp.Client, input SFTPInput) (string, error) {
	if err := validateLocalPath(input.LocalPath); err != nil {
		return "", err
	}
	if err := validateRemotePath(input.RemotePath); err != nil {
		return "", err
	}

	// Check local file
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

	// Check overwrite
	if !common.FlexBool(input.Overwrite) {
		if _, err := client.Stat(input.RemotePath); err == nil {
			return "", fmt.Errorf("remote file already exists: %s (use overwrite=true to replace)", input.RemotePath)
		}
	}

	// Open local file
	localFile, err := os.Open(input.LocalPath)
	if err != nil {
		return "", fmt.Errorf("open local file: %w", err)
	}
	defer localFile.Close()

	// Create remote file
	remoteFile, err := client.Create(input.RemotePath)
	if err != nil {
		return "", fmt.Errorf("create remote file: %w", err)
	}
	defer remoteFile.Close()

	// Transfer
	written, err := io.Copy(remoteFile, localFile)
	if err != nil {
		remoteFile.Close()
		client.Remove(input.RemotePath) // clean up partial remote file
		return "", fmt.Errorf("upload failed: %w", err)
	}

	return fmt.Sprintf("Uploaded %s -> %s (%s)", input.LocalPath, input.RemotePath, formatSize(written)), nil
}

// opDownload transfers a remote file to the local machine.
func opDownload(client *sftp.Client, input SFTPInput) (string, error) {
	if err := validateRemotePath(input.RemotePath); err != nil {
		return "", err
	}
	if err := validateLocalPath(input.LocalPath); err != nil {
		return "", err
	}
	if err := isSensitiveLocalPath(input.LocalPath); err != nil {
		return "", err
	}

	// Check remote file
	remoteInfo, err := client.Stat(input.RemotePath)
	if err != nil {
		return "", fmt.Errorf("remote file: %w", err)
	}
	if remoteInfo.IsDir() {
		return "", fmt.Errorf("remote_path is a directory, not a file")
	}
	if remoteInfo.Size() > maxTransferSize {
		return "", fmt.Errorf("file too large: %s (max %s)", formatSize(remoteInfo.Size()), formatSize(maxTransferSize))
	}

	// Check overwrite
	if !common.FlexBool(input.Overwrite) {
		if _, err := os.Stat(input.LocalPath); err == nil {
			return "", fmt.Errorf("local file already exists: %s (use overwrite=true to replace)", input.LocalPath)
		}
	}

	// Create local directory if needed
	localDir := filepath.Dir(input.LocalPath)
	if err := os.MkdirAll(localDir, 0755); err != nil {
		return "", fmt.Errorf("create local directory: %w", err)
	}

	// Open remote file
	remoteFile, err := client.Open(input.RemotePath)
	if err != nil {
		return "", fmt.Errorf("open remote file: %w", err)
	}
	defer remoteFile.Close()

	// Create local file
	localFile, err := os.Create(input.LocalPath)
	if err != nil {
		return "", fmt.Errorf("create local file: %w", err)
	}

	// Transfer
	written, err := io.Copy(localFile, remoteFile)
	closeErr := localFile.Close()
	if err != nil {
		os.Remove(input.LocalPath) // clean up partial file
		return "", fmt.Errorf("download failed: %w", err)
	}
	if closeErr != nil {
		os.Remove(input.LocalPath) // close failed, file may be incomplete
		return "", fmt.Errorf("download failed (close): %w", closeErr)
	}

	return fmt.Sprintf("Downloaded %s -> %s (%s)", input.RemotePath, input.LocalPath, formatSize(written)), nil
}

// opLs lists the contents of a remote directory.
func opLs(client *sftp.Client, input SFTPInput) (string, error) {
	if err := validateRemotePath(input.RemotePath); err != nil {
		return "", err
	}

	entries, err := client.ReadDir(input.RemotePath)
	if err != nil {
		return "", fmt.Errorf("read directory: %w", err)
	}

	// Sort: directories first, then by name
	sort.Slice(entries, func(i, j int) bool {
		di, dj := entries[i].IsDir(), entries[j].IsDir()
		if di != dj {
			return di
		}
		return entries[i].Name() < entries[j].Name()
	})

	var sb strings.Builder
	total := len(entries)
	truncated := false
	if total > maxListEntries {
		entries = entries[:maxListEntries]
		truncated = true
	}

	sb.WriteString(fmt.Sprintf("Directory: %s (%d entries)\n", input.RemotePath, total))

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}
		sb.WriteString(fmt.Sprintf("%-12s %10s  %s  %s\n",
			entry.Mode().String(),
			formatSize(entry.Size()),
			entry.ModTime().Format("2006-01-02 15:04"),
			name,
		))
	}

	if truncated {
		sb.WriteString(fmt.Sprintf("\n... truncated (%d entries shown of %d total)\n", maxListEntries, total))
	}

	return sb.String(), nil
}

// opStat returns information about a remote file or directory.
func opStat(client *sftp.Client, input SFTPInput) (string, error) {
	if err := validateRemotePath(input.RemotePath); err != nil {
		return "", err
	}

	info, err := client.Lstat(input.RemotePath)
	if err != nil {
		return "", fmt.Errorf("stat: %w", err)
	}

	fileType := "file"
	if info.IsDir() {
		fileType = "directory"
	}
	if info.Mode()&os.ModeSymlink != 0 {
		fileType = "symlink"
		// Resolve symlink target
		if target, err := client.ReadLink(input.RemotePath); err == nil {
			fileType = fmt.Sprintf("symlink -> %s", target)
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Path: %s\n", input.RemotePath))
	sb.WriteString(fmt.Sprintf("Type: %s\n", fileType))
	sb.WriteString(fmt.Sprintf("Size: %s (%d bytes)\n", formatSize(info.Size()), info.Size()))
	sb.WriteString(fmt.Sprintf("Mode: %s (%04o)\n", info.Mode().String(), info.Mode().Perm()))
	sb.WriteString(fmt.Sprintf("Modified: %s\n", info.ModTime().Format("2006-01-02 15:04:05 MST")))

	return sb.String(), nil
}

// opMkdir creates a remote directory.
func opMkdir(client *sftp.Client, input SFTPInput) (string, error) {
	if err := validateRemotePath(input.RemotePath); err != nil {
		return "", err
	}

	if common.FlexBool(input.Recursive) {
		if err := client.MkdirAll(input.RemotePath); err != nil {
			return "", fmt.Errorf("mkdir -p: %w", err)
		}
	} else {
		if err := client.Mkdir(input.RemotePath); err != nil {
			return "", fmt.Errorf("mkdir: %w", err)
		}
	}

	return fmt.Sprintf("Created directory: %s", input.RemotePath), nil
}

// opRm removes a remote file or directory.
func opRm(client *sftp.Client, input SFTPInput) (string, error) {
	if err := validateRemotePath(input.RemotePath); err != nil {
		return "", err
	}

	if !common.FlexBool(input.Recursive) {
		// Simple remove (file or empty directory)
		if err := client.Remove(input.RemotePath); err != nil {
			return "", fmt.Errorf("remove: %w", err)
		}
		return fmt.Sprintf("Removed: %s", input.RemotePath), nil
	}

	// Recursive delete
	if isDangerousPath(input.RemotePath) {
		return "", fmt.Errorf("refusing to recursively delete dangerous path: %s", input.RemotePath)
	}

	// Verify it's a directory
	info, err := client.Stat(input.RemotePath)
	if err != nil {
		return "", fmt.Errorf("stat: %w", err)
	}
	if !info.IsDir() {
		// Not a directory, just remove the file
		if err := client.Remove(input.RemotePath); err != nil {
			return "", fmt.Errorf("remove: %w", err)
		}
		return fmt.Sprintf("Removed: %s", input.RemotePath), nil
	}

	// Walk and collect all entries (depth-first, files before directories)
	files, dirs, err := walkRemoteDir(client, input.RemotePath, 0)
	if err != nil {
		return "", err
	}

	// Delete files first, then directories (deepest first)
	totalDeleted := 0
	for _, f := range files {
		if err := client.Remove(f); err != nil {
			return "", fmt.Errorf("remove %s: %w (deleted %d items so far)", f, err, totalDeleted)
		}
		totalDeleted++
	}
	for _, d := range dirs {
		if err := client.RemoveDirectory(d); err != nil {
			return "", fmt.Errorf("rmdir %s: %w (deleted %d items so far)", d, err, totalDeleted)
		}
		totalDeleted++
	}

	// Remove the root directory itself
	if err := client.RemoveDirectory(input.RemotePath); err != nil {
		return "", fmt.Errorf("rmdir %s: %w", input.RemotePath, err)
	}
	totalDeleted++

	return fmt.Sprintf("Removed directory tree: %s (%d files, %d dirs)",
		input.RemotePath, len(files), len(dirs)+1), nil
}

const maxRecurseDepth = 100

// walkRemoteDir collects files and directories recursively for deletion.
// Returns files (leaf-first) and directories (deepest-first).
func walkRemoteDir(client *sftp.Client, dir string, depth int) (files []string, dirs []string, err error) {
	if depth > maxRecurseDepth {
		return nil, nil, fmt.Errorf("recursive delete exceeded depth limit (%d levels)", maxRecurseDepth)
	}

	entries, err := client.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("read directory %s: %w", dir, err)
	}

	for _, entry := range entries {
		// Skip symlinks to avoid traversal attacks
		if entry.Mode()&os.ModeSymlink != 0 {
			continue
		}

		fullPath := dir + "/" + entry.Name()

		if entry.IsDir() {
			// Recurse
			subFiles, subDirs, err := walkRemoteDir(client, fullPath, depth+1)
			if err != nil {
				return nil, nil, err
			}

			totalItems := len(files) + len(dirs) + len(subFiles) + len(subDirs)
			if totalItems > maxDeleteItems {
				return nil, nil, fmt.Errorf("recursive delete exceeded %d items limit", maxDeleteItems)
			}

			files = append(files, subFiles...)
			dirs = append(dirs, subDirs...)
			dirs = append(dirs, fullPath) // parent after children
		} else {
			files = append(files, fullPath)

			if len(files)+len(dirs) > maxDeleteItems {
				return nil, nil, fmt.Errorf("recursive delete exceeded %d items limit", maxDeleteItems)
			}
		}
	}

	return files, dirs, nil
}

// opChmod changes the permissions of a remote file or directory.
func opChmod(client *sftp.Client, input SFTPInput) (string, error) {
	if err := validateRemotePath(input.RemotePath); err != nil {
		return "", err
	}
	if input.Mode == "" {
		return "", fmt.Errorf("mode is required for chmod (e.g. \"0755\")")
	}

	parsed, err := strconv.ParseUint(input.Mode, 8, 32)
	if err != nil {
		return "", fmt.Errorf("invalid mode %q: must be octal (e.g. \"0755\")", input.Mode)
	}
	if parsed > 0777 {
		return "", fmt.Errorf("mode %04o sets setuid/setgid/sticky bits; max allowed is 0777", parsed)
	}

	if err := client.Chmod(input.RemotePath, os.FileMode(parsed)); err != nil {
		return "", fmt.Errorf("chmod: %w", err)
	}

	return fmt.Sprintf("Changed mode of %s to %04o", input.RemotePath, parsed), nil
}

// opRename renames or moves a remote file or directory.
func opRename(client *sftp.Client, input SFTPInput) (string, error) {
	if err := validateRemotePath(input.RemotePath); err != nil {
		return "", err
	}
	if err := validateRemotePath(input.NewPath); err != nil {
		return "", fmt.Errorf("new_path: %w", err)
	}

	// Verify source exists
	if _, err := client.Stat(input.RemotePath); err != nil {
		return "", fmt.Errorf("source: %w", err)
	}

	// Check if destination already exists
	if !common.FlexBool(input.Overwrite) {
		if _, err := client.Stat(input.NewPath); err == nil {
			return "", fmt.Errorf("destination already exists: %s (use overwrite=true to replace)", input.NewPath)
		}
	}

	if err := client.PosixRename(input.RemotePath, input.NewPath); err != nil {
		return "", fmt.Errorf("rename: %w", err)
	}

	return fmt.Sprintf("Renamed: %s -> %s", input.RemotePath, input.NewPath), nil
}
