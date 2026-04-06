package backup

import (
	"archive/zip"
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type BackupInput struct {
	Source       string   `json:"source" jsonschema:"Absolute path to the directory to backup"`
	OutputDir    string   `json:"output_dir,omitempty" jsonschema:"Absolute path to the backup output directory. Default: ./backups/"`
	Excludes     []string `json:"excludes,omitempty" jsonschema:"Glob patterns to exclude (e.g. node_modules, *.log, .git)"`
	ExcludesFile string   `json:"excludes_file,omitempty" jsonschema:"Absolute path to a file containing exclude patterns (one per line). Lines starting with # are comments. Patterns are appended to excludes list"`
	DryRun       interface{} `json:"dry_run,omitempty" jsonschema:"Preview backup without creating archive: true or false. Shows summary with directory counts, exclude pattern matches, and largest files. Default: false"`
}

type BackupOutput struct {
	Result      string `json:"result"`
	ArchivePath string `json:"archive_path,omitempty"`
	FileCount   int    `json:"file_count"`
}

// Default exclude patterns
var defaultExcludes = []string{
	".git",
	"node_modules",
	"__pycache__",
	".cache",
	"*.exe",
	"*.dll",
	"*.so",
	"*.dylib",
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input BackupInput) (*mcp.CallToolResult, BackupOutput, error) {
	if input.Source == "" {
		return errorResult("source is required")
	}
	if !filepath.IsAbs(input.Source) {
		return errorResult("source must be an absolute path")
	}

	fi, err := os.Stat(input.Source)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("source not found: %s", input.Source))
		}
		return errorResult(fmt.Sprintf("cannot access source: %v", err))
	}
	if !fi.IsDir() {
		return errorResult("source must be a directory")
	}

	// Output directory
	outputDir := input.OutputDir
	if outputDir != "" && !filepath.IsAbs(outputDir) {
		return errorResult("output_dir must be an absolute path")
	}
	if outputDir == "" {
		outputDir = filepath.Join(input.Source, "backups")
	}

	// Timestamp filename
	dirName := filepath.Base(input.Source)
	timestamp := time.Now().Format("20060102_150405")
	archivePath := filepath.Join(outputDir, fmt.Sprintf("%s_%s.zip", dirName, timestamp))

	// Exclude patterns (default + user-specified + file-based)
	excludes := append([]string{}, defaultExcludes...)
	excludes = append(excludes, input.Excludes...)

	// Load patterns from excludes_file if specified
	if input.ExcludesFile != "" {
		if !filepath.IsAbs(input.ExcludesFile) {
			return errorResult("excludes_file must be an absolute path")
		}
		filePatterns, err := loadExcludesFile(input.ExcludesFile)
		if err != nil {
			return errorResult(fmt.Sprintf("failed to read excludes_file: %v", err))
		}
		excludes = append(excludes, filePatterns...)
	}

	// Normalize backup output directory to prevent infinite loop
	absOutputDir, _ := filepath.Abs(outputDir)

	if common.FlexBool(input.DryRun) {
		return dryRun(input.Source, excludes, absOutputDir, archivePath)
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return errorResult(fmt.Sprintf("failed to create output directory: %v", err))
	}

	count, err := createBackupZip(archivePath, input.Source, excludes, absOutputDir)
	if err != nil {
		os.Remove(archivePath) // clean up incomplete zip
		return errorResult(fmt.Sprintf("backup failed: %v", err))
	}

	msg := fmt.Sprintf("OK: backed up %d files → %s", count, archivePath)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, BackupOutput{Result: msg, ArchivePath: archivePath, FileCount: count}, nil
}

// dryRunStats collects statistics during dry run walk.
type dryRunStats struct {
	includeCount    int
	includeSize     int64
	excludeCount    int
	dirCounts       map[string]int      // top-level dir → file count
	dirSizes        map[string]int64    // top-level dir → total size
	patternMatches  map[string]int      // exclude pattern → match count
	largestFiles    []fileEntry         // sorted by size desc
}

type fileEntry struct {
	path string
	size int64
}

func dryRun(sourceDir string, excludes []string, backupDir string, archivePath string) (*mcp.CallToolResult, BackupOutput, error) {
	stats := &dryRunStats{
		dirCounts:      make(map[string]int),
		dirSizes:       make(map[string]int64),
		patternMatches: make(map[string]int),
	}

	err := filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip backup output directory (with boundary check to avoid false prefix match)
		absPath, _ := filepath.Abs(path)
		if absPath == backupDir || strings.HasPrefix(absPath, backupDir+string(filepath.Separator)) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip symlinks to prevent directory traversal
		linfo, lerr := os.Lstat(path)
		if lerr == nil && linfo.Mode()&os.ModeSymlink != 0 {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		rel, _ := filepath.Rel(sourceDir, path)
		relSlash := filepath.ToSlash(rel)

		// Check exclusion and track which pattern matched
		if matchedPattern := matchExcludePattern(info.Name(), relSlash, info.IsDir(), excludes); matchedPattern != "" {
			stats.patternMatches[matchedPattern]++
			if info.IsDir() {
				stats.excludeCount++ // count the directory itself
				return filepath.SkipDir
			}
			stats.excludeCount++
			return nil
		}

		if info.IsDir() {
			return nil
		}

		// Included file
		stats.includeCount++
		stats.includeSize += info.Size()

		// Track directory stats (first path component)
		topDir := topDirectory(relSlash)
		stats.dirCounts[topDir]++
		stats.dirSizes[topDir] += info.Size()

		// Track largest files (keep top 5)
		stats.largestFiles = append(stats.largestFiles, fileEntry{path: relSlash, size: info.Size()})
		if len(stats.largestFiles) > 50 {
			// Periodically trim to avoid memory bloat
			sort.Slice(stats.largestFiles, func(i, j int) bool {
				return stats.largestFiles[i].size > stats.largestFiles[j].size
			})
			stats.largestFiles = stats.largestFiles[:5]
		}

		return nil
	})
	if err != nil {
		return errorResult(fmt.Sprintf("dry run walk failed: %v", err))
	}

	// Sort largest files
	sort.Slice(stats.largestFiles, func(i, j int) bool {
		return stats.largestFiles[i].size > stats.largestFiles[j].size
	})
	if len(stats.largestFiles) > 5 {
		stats.largestFiles = stats.largestFiles[:5]
	}

	// Build output
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[dry_run] Backup preview: %s\n\n", sourceDir))

	// Summary
	sb.WriteString("=== Summary ===\n")
	sb.WriteString(fmt.Sprintf("  Include: %d files (%s)\n", stats.includeCount, formatSize(stats.includeSize)))
	sb.WriteString(fmt.Sprintf("  Exclude: %d files/directories\n", stats.excludeCount))

	// Top included directories
	if len(stats.dirCounts) > 0 {
		sb.WriteString("\n=== Top included directories ===\n")
		type dirStat struct {
			name  string
			count int
			size  int64
		}
		var dirs []dirStat
		for name, count := range stats.dirCounts {
			dirs = append(dirs, dirStat{name: name, count: count, size: stats.dirSizes[name]})
		}
		sort.Slice(dirs, func(i, j int) bool {
			return dirs[i].count > dirs[j].count
		})
		limit := 10
		if len(dirs) < limit {
			limit = len(dirs)
		}
		for _, d := range dirs[:limit] {
			sb.WriteString(fmt.Sprintf("  %-40s %5d files  %s\n", d.name+"/", d.count, formatSize(d.size)))
		}
	}

	// Exclude pattern matches
	if len(stats.patternMatches) > 0 {
		sb.WriteString("\n=== Exclude pattern matches ===\n")
		type patternStat struct {
			pattern string
			count   int
		}
		var patterns []patternStat
		for p, c := range stats.patternMatches {
			patterns = append(patterns, patternStat{pattern: p, count: c})
		}
		sort.Slice(patterns, func(i, j int) bool {
			return patterns[i].count > patterns[j].count
		})
		for _, p := range patterns {
			sb.WriteString(fmt.Sprintf("  %-40s %5d matches\n", p.pattern, p.count))
		}
	}

	// Largest files
	if len(stats.largestFiles) > 0 {
		sb.WriteString("\n=== Largest files ===\n")
		for _, f := range stats.largestFiles {
			sb.WriteString(fmt.Sprintf("  %-60s %s\n", f.path, formatSize(f.size)))
		}
	}

	sb.WriteString(fmt.Sprintf("\n=== Output ===\n  → %s\n", archivePath))

	result := sb.String()
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, BackupOutput{Result: result, FileCount: stats.includeCount}, nil
}

// matchExcludePattern returns the first matching exclude pattern, or "" if none match.
func matchExcludePattern(name string, relPath string, isDir bool, excludes []string) string {
	for _, pattern := range excludes {
		if isDir && name == pattern {
			return pattern
		}
		if matched, _ := filepath.Match(pattern, name); matched {
			return pattern
		}
		if strings.Contains(pattern, "/") || strings.Contains(pattern, string(filepath.Separator)) {
			normalizedPattern := filepath.ToSlash(pattern)
			if matched, _ := filepath.Match(normalizedPattern, relPath); matched {
				return pattern
			}
			if isDir {
				trimmed := strings.TrimSuffix(normalizedPattern, "/*")
				if trimmed != normalizedPattern && relPath == trimmed {
					return pattern
				}
			}
		}
	}
	return ""
}

// topDirectory returns the first path component (top-level directory).
func topDirectory(relPath string) string {
	parts := strings.SplitN(relPath, "/", 2)
	if len(parts) == 1 {
		return "."
	}
	return parts[0]
}

func formatSize(bytes int64) string {
	if bytes >= 1024*1024*1024 {
		return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
	}
	if bytes >= 1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
	if bytes >= 1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%d B", bytes)
}

func createBackupZip(output, sourceDir string, excludes []string, backupDir string) (int, error) {
	f, err := os.Create(output)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	w := zip.NewWriter(f)
	defer w.Close()

	count := 0
	err = filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip backup output directory (with boundary check to avoid false prefix match)
		absPath, _ := filepath.Abs(path)
		if absPath == backupDir || strings.HasPrefix(absPath, backupDir+string(filepath.Separator)) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip symlinks to prevent directory traversal
		linfo, lerr := os.Lstat(path)
		if lerr == nil && linfo.Mode()&os.ModeSymlink != 0 {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Check exclude patterns
		rel, _ := filepath.Rel(sourceDir, path)
		relSlash := filepath.ToSlash(rel)
		if shouldExclude(info.Name(), relSlash, info.IsDir(), excludes) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if info.IsDir() {
			return nil
		}

		archivePath := relSlash

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return nil
		}
		header.Name = archivePath
		header.Method = zip.Deflate

		writer, err := w.CreateHeader(header)
		if err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return nil // skip unreadable files
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		if err != nil {
			return nil
		}

		count++
		return nil
	})

	return count, err
}

func shouldExclude(name string, relPath string, isDir bool, excludes []string) bool {
	return matchExcludePattern(name, relPath, isDir, excludes) != ""
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "backup",
		Description: `Creates a timestamped zip backup of a directory.
Output: {dirname}_{YYYYMMDD_HHMMSS}.zip
Default excludes: .git, node_modules, __pycache__, binaries.
Custom excludes can be added via the excludes parameter.`,
	}, Handle)
}

// loadExcludesFile reads exclude patterns from a file (one per line).
// Empty lines and lines starting with # are ignored.
func loadExcludesFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var patterns []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return patterns, nil
}

func errorResult(msg string) (*mcp.CallToolResult, BackupOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, BackupOutput{}, nil
}
