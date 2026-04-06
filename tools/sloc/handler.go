package sloc

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type SlocInput struct {
	Path       string `json:"path,omitempty" jsonschema:"Absolute path to a file or directory to count,required"`
	FilePath   string `json:"file_path,omitempty" jsonschema:"Alias for path"`
	Glob       string `json:"glob,omitempty" jsonschema:"Glob pattern to filter files when path is a directory (e.g. *.go, *.py). Default: all recognized source files"`
	MaxDepth   int    `json:"max_depth,omitempty" jsonschema:"Maximum directory depth to traverse (0 = unlimited). Default: 0"`
	ShowFiles  *bool  `json:"show_files,omitempty" jsonschema:"Show per-file breakdown. Default: true for <=50 files, false otherwise"`
	SkipBlank  interface{} `json:"skip_blank,omitempty" jsonschema:"Exclude blank lines from count: true or false. Default: false"`
}

type SlocOutput struct {
	Result string `json:"result"`
}

// Language definition: extensions → language name
var langMap = map[string]string{
	".go":     "Go",
	".py":     "Python",
	".js":     "JavaScript",
	".jsx":    "JavaScript",
	".ts":     "TypeScript",
	".tsx":    "TypeScript",
	".java":   "Java",
	".kt":     "Kotlin",
	".kts":    "Kotlin",
	".rs":     "Rust",
	".c":      "C",
	".h":      "C/C++ Header",
	".cpp":    "C++",
	".cc":     "C++",
	".cxx":    "C++",
	".hpp":    "C++ Header",
	".cs":     "C#",
	".rb":     "Ruby",
	".php":    "PHP",
	".swift":  "Swift",
	".m":      "Objective-C",
	".mm":     "Objective-C++",
	".r":      "R",
	".R":      "R",
	".lua":    "Lua",
	".pl":     "Perl",
	".pm":     "Perl",
	".sh":     "Shell",
	".bash":   "Shell",
	".zsh":    "Shell",
	".fish":   "Shell",
	".ps1":    "PowerShell",
	".psm1":   "PowerShell",
	".bat":    "Batch",
	".cmd":    "Batch",
	".sql":    "SQL",
	".html":   "HTML",
	".htm":    "HTML",
	".css":    "CSS",
	".scss":   "SCSS",
	".sass":   "SASS",
	".less":   "LESS",
	".vue":    "Vue",
	".svelte": "Svelte",
	".xml":    "XML",
	".json":   "JSON",
	".yaml":   "YAML",
	".yml":    "YAML",
	".toml":   "TOML",
	".ini":    "INI",
	".cfg":    "Config",
	".conf":   "Config",
	".md":     "Markdown",
	".rst":    "reStructuredText",
	".tex":    "LaTeX",
	".proto":  "Protocol Buffers",
	".graphql":"GraphQL",
	".gql":    "GraphQL",
	".dart":   "Dart",
	".ex":     "Elixir",
	".exs":    "Elixir",
	".erl":    "Erlang",
	".hrl":    "Erlang",
	".hs":     "Haskell",
	".ml":     "OCaml",
	".mli":    "OCaml",
	".fs":     "F#",
	".fsx":    "F#",
	".clj":    "Clojure",
	".scala":  "Scala",
	".groovy": "Groovy",
	".gradle": "Gradle",
	".tf":     "Terraform",
	".hcl":    "HCL",
	".dockerfile": "Dockerfile",
	".makefile":    "Makefile",
}

// Directories to always skip
var skipDirs = map[string]bool{
	".git": true, ".svn": true, ".hg": true,
	"node_modules": true, "vendor": true, "__pycache__": true,
	".tox": true, ".venv": true, "venv": true,
	"dist": true, "build": true, "target": true,
	".idea": true, ".vscode": true,
}

type fileStat struct {
	path  string
	lang  string
	lines int
	blank int
}

type langStat struct {
	files int
	lines int
	blank int
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input SlocInput) (*mcp.CallToolResult, SlocOutput, error) {
	if input.Path == "" {
		input.Path = input.FilePath
	}
	if input.Path == "" {
		return errorResult("path is required")
	}
	if !filepath.IsAbs(input.Path) {
		return errorResult("path must be absolute")
	}

	cleaned := filepath.Clean(input.Path)
	info, err := os.Stat(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("path not found: %s", cleaned))
		}
		return errorResult(fmt.Sprintf("cannot access path: %v", err))
	}

	skipBlank := common.FlexBool(input.SkipBlank)

	var files []fileStat

	if info.IsDir() {
		files, err = walkDir(cleaned, input.Glob, input.MaxDepth, skipBlank)
		if err != nil {
			return errorResult(fmt.Sprintf("walk error: %v", err))
		}
	} else {
		// Single file
		lang := detectLang(cleaned)
		if lang == "" {
			lang = "Unknown"
		}
		lines, blank, ferr := countLines(cleaned)
		if ferr != nil {
			return errorResult(fmt.Sprintf("read error: %v", ferr))
		}
		files = append(files, fileStat{path: cleaned, lang: lang, lines: lines, blank: blank})
	}

	if len(files) == 0 {
		return errorResult("no source files found")
	}

	// Aggregate by language
	langs := make(map[string]*langStat)
	totalLines := 0
	totalBlank := 0
	for _, f := range files {
		s, ok := langs[f.lang]
		if !ok {
			s = &langStat{}
			langs[f.lang] = s
		}
		s.files++
		s.lines += f.lines
		s.blank += f.blank
		totalLines += f.lines
		totalBlank += f.blank
	}

	// Sort languages by lines descending
	type langEntry struct {
		name string
		stat *langStat
	}
	var sorted []langEntry
	for name, stat := range langs {
		sorted = append(sorted, langEntry{name, stat})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].stat.lines > sorted[j].stat.lines
	})

	// Build output
	var sb strings.Builder

	// Per-file breakdown
	showFiles := len(files) <= 50
	if input.ShowFiles != nil {
		showFiles = *input.ShowFiles
	}
	if showFiles {
		// Sort files by lines descending
		sort.Slice(files, func(i, j int) bool {
			return files[i].lines > files[j].lines
		})

		sb.WriteString("Files:\n")
		for _, f := range files {
			rel := f.path
			if info.IsDir() {
				if r, err := filepath.Rel(cleaned, f.path); err == nil {
					rel = r
				}
			}
			if skipBlank {
				sb.WriteString(fmt.Sprintf("  %6d  %s  (%s)\n", f.lines-f.blank, filepath.ToSlash(rel), f.lang))
			} else {
				sb.WriteString(fmt.Sprintf("  %6d  %s  (%s)\n", f.lines, filepath.ToSlash(rel), f.lang))
			}
		}
		sb.WriteString("\n")
	}

	// Language summary table
	sb.WriteString("Language          Files    Lines")
	if !skipBlank {
		sb.WriteString("    Blank")
	}
	sb.WriteString("\n")
	sb.WriteString("────────────────  ─────  ───────")
	if !skipBlank {
		sb.WriteString("  ───────")
	}
	sb.WriteString("\n")

	for _, e := range sorted {
		displayLines := e.stat.lines
		if skipBlank {
			displayLines = e.stat.lines - e.stat.blank
		}
		line := fmt.Sprintf("%-16s  %5d  %7d", e.name, e.stat.files, displayLines)
		if !skipBlank {
			line += fmt.Sprintf("  %7d", e.stat.blank)
		}
		sb.WriteString(line + "\n")
	}

	sb.WriteString("────────────────  ─────  ───────")
	if !skipBlank {
		sb.WriteString("  ───────")
	}
	sb.WriteString("\n")

	displayTotal := totalLines
	if skipBlank {
		displayTotal = totalLines - totalBlank
	}
	totalLine := fmt.Sprintf("%-16s  %5d  %7d", "TOTAL", len(files), displayTotal)
	if !skipBlank {
		totalLine += fmt.Sprintf("  %7d", totalBlank)
	}
	sb.WriteString(totalLine + "\n")

	result := sb.String()
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, SlocOutput{Result: result}, nil
}

func walkDir(root, globPattern string, maxDepth int, skipBlank bool) ([]fileStat, error) {
	var files []fileStat
	rootDepth := strings.Count(filepath.ToSlash(root), "/")

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible
		}

		if d.IsDir() {
			name := d.Name()
			if skipDirs[name] {
				return filepath.SkipDir
			}
			if maxDepth > 0 {
				depth := strings.Count(filepath.ToSlash(path), "/") - rootDepth
				if depth >= maxDepth {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Check glob pattern if provided
		if globPattern != "" {
			matched, err := filepath.Match(globPattern, d.Name())
			if err != nil || !matched {
				return nil
			}
		}

		lang := detectLang(path)
		if lang == "" {
			// Also check special filenames
			lang = detectByName(d.Name())
			if lang == "" {
				return nil // skip unrecognized files
			}
		}

		lines, blank, err := countLines(path)
		if err != nil {
			return nil // skip unreadable files
		}

		files = append(files, fileStat{path: path, lang: lang, lines: lines, blank: blank})
		return nil
	})

	return files, err
}

func countLines(path string) (total int, blank int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Increase buffer for very long lines
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		total++
		if strings.TrimSpace(scanner.Text()) == "" {
			blank++
		}
	}
	if err := scanner.Err(); err != nil {
		return total, blank, err
	}
	return total, blank, nil
}

func detectLang(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	if lang, ok := langMap[ext]; ok {
		return lang
	}
	return ""
}

func detectByName(name string) string {
	lower := strings.ToLower(name)
	switch {
	case lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile."):
		return "Dockerfile"
	case lower == "makefile" || lower == "gnumakefile":
		return "Makefile"
	case lower == "cmakelists.txt" || strings.HasSuffix(lower, ".cmake"):
		return "CMake"
	case lower == "vagrantfile":
		return "Ruby"
	case lower == "rakefile" || lower == "gemfile":
		return "Ruby"
	case lower == "justfile":
		return "Just"
	case lower == ".gitignore" || lower == ".dockerignore" || lower == ".editorconfig":
		return "Config"
	}
	return ""
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "sloc",
		Description: `Count source lines of code (SLOC) in files or directories.
Returns per-language summary with file count, total lines, and blank lines.
Recognizes 70+ languages by file extension.
Skips common non-source directories (node_modules, .git, vendor, dist, build).
Use glob to filter specific file types. Use show_files to control per-file breakdown.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, SlocOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, SlocOutput{Result: msg}, nil
}
