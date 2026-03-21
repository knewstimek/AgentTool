package help

import (
	"context"
	"fmt"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type HelpInput struct {
	Topic string `json:"topic,omitempty" jsonschema:"Help topic. Available: overview, encoding, indentation, tools, debug, analyze, memtool, wintool, troubleshooting. Empty = overview"`
}

type HelpOutput struct {
	Content string `json:"content"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input HelpInput) (*mcp.CallToolResult, HelpOutput, error) {
	topic := strings.ToLower(strings.TrimSpace(input.Topic))
	if topic == "" {
		topic = "overview"
	}

	text := ""
	switch topic {
	case "overview":
		text = helpOverview()
	case "encoding":
		text = helpEncoding()
	case "indentation", "indent":
		text = helpIndentation()
	case "tools":
		text = helpTools()
	case "debug", "debugger", "dap":
		text = helpDebug()
	case "analyze", "binary", "disassemble", "pe":
		text = helpAnalyze()
	case "memtool", "memscan", "memory", "scan":
		text = helpMemtool()
	case "wintool", "window", "win", "gui":
		text = helpWintool()
	case "troubleshooting", "trouble":
		text = helpTroubleshooting()
	default:
		text = "Unknown topic: " + topic + "\n\n" +
			"Available topics: overview, encoding, indentation, tools, debug, analyze, memtool, wintool, troubleshooting"
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, HelpOutput{Content: text}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "agent_tool_help",
		Description: `Returns usage guide for agent-tool.
Call this when you encounter encoding warnings, garbled text, or need to understand agent-tool features.
Topics: overview, encoding, indentation, tools, debug, analyze, troubleshooting.`,
	}, Handle)
}

func helpOverview() string {
	return `# agent-tool — MCP Tool Server for AI Coding Agents

agent-tool provides encoding-aware and indentation-aware file tools.
It auto-detects file encoding and indentation style, preserving them across edits.

## Current Configuration
- Fallback encoding: ` + common.GetFallbackEncoding() + `

## Available Tools
- edit: String replacement with smart indentation + encoding preservation (supports dry_run)
- read: Encoding-aware file reading with line range support
- write: Encoding-aware file creation/overwrite
- grep: Encoding-aware regex content search
- glob: File pattern matching with ** recursive support
- listdir: Directory listing (flat or tree)
- compress: Create zip / tar.gz archives
- decompress: Extract zip / tar.gz archives
- backup: Timestamped zip backup with exclude patterns
- convert_encoding: Convert file encoding (EUC-KR ↔ UTF-8, BOM, etc.)
- checksum: Compute file hash (md5, sha1, sha256)
- file_info: File metadata (size, encoding, line ending, indentation, line count)
- diff: Compare two files (unified diff output)
- patch: Apply unified diff patch to a file (supports dry_run)
- delete: Delete a single file (no directories, no symlinks, supports dry_run)
- rename: Rename or move a file/directory (atomic, supports dry_run)
- sysinfo: System information (OS, CPU, RAM, disk, uptime, CPU usage measurement)
- find_tools: Discover installed dev tools (compilers, runtimes, build systems)
- proclist: List running processes with PID, name, command line, memory (sensitive args masked)
- prockill: Kill, suspend, or resume processes by PID or port (tree kill, signal selection, zombie handling, dry_run)
- procexec: Execute commands as new processes (background, suspended start, timeout)
- envvar: Read environment variables (sensitive values masked)
- firewall: Read firewall rules (iptables/nftables/netsh, read-only)
- ssh: Execute commands on remote servers via SSH (IPv4/IPv6, ProxyJump, session pooling)
- sftp: Transfer files and manage remote filesystems over SSH (upload, download, ls, stat, mkdir, rm, chmod, rename, async transfers)
- bash: Persistent shell sessions with working directory and environment variable retention
- webfetch: Fetch web content as text/Markdown with ECH, DoH, proxy, and SSRF protection
- websearch: Web search via Brave Search or Naver API (requires API key env vars)
- download: Download files from URLs with ECH, DoH, proxy, and SSRF protection
- httpreq: Execute HTTP requests with any method (POST, PUT, DELETE, etc.) for API testing
- copy: Copy files or directories (recursive, atomic write, permissions preserved, dry_run)
- mkdir: Create directories with optional permission mode (recursive by default)
- multiread: Read multiple files in one call (reduces API round-trips)
- regexreplace: Regex find-and-replace across files or directories (capture groups, encoding-aware, dry_run)
- jsonquery: Query JSON files with dot-notation paths to extract specific values (saves tokens)
- yamlquery: Query YAML files with dot-notation paths (same syntax as jsonquery)
- tomlquery: Query TOML files with dot-notation paths (same syntax as jsonquery)
- portcheck: Check if a TCP port is open on a host (connectivity test)
- tlscheck: Check TLS certificate of a host (expiry, issuer, SANs, protocol, cipher)
- dnslookup: DNS record lookup (A, AAAA, MX, CNAME, TXT, NS, SOA) with DoH support
- mysql: Execute MySQL/MariaDB queries (SELECT → table format, DML → affected rows)
- redis: Execute Redis commands (any command, result formatting)
- externalip: Get your external (public) IP address
- sloc: Count source lines of code (SLOC) with per-language summary
- debug: Interactive debugger via DAP (breakpoints, stepping, variables, stack traces)
- analyze: Static binary analysis (20 operations: disassemble, PE/ELF/Mach-O parsing, imphash, Rich header, resources, DWARF, strings, hexdump, pattern search, entropy, overlay, binary diff, xref, function_at, call_graph, follow_ptr, rtti_dump, struct_layout)
- set_config: Change runtime settings (encoding, file size, SSRF policy, DoH/ECH toggle)
- agent_tool_help: This help tool

## Quick Tips
- Use 'agent_tool_help' with topic='encoding' for encoding setup guide
- Use 'agent_tool_help' with topic='troubleshooting' for common issues`
}

func helpEncoding() string {
	return `# Encoding Guide

## How encoding detection works
Priority order:
1. .editorconfig 'charset' value (highest priority)
2. chardet auto-detection (confidence >= 50%)
3. Fallback encoding (currently: ` + common.GetFallbackEncoding() + `)

## Setting up for non-UTF-8 projects

### Option 1: .editorconfig (recommended)
Add to your project's .editorconfig:
  [*]
  charset = euc-kr

This is the most reliable method. The charset value is used directly without auto-detection.

### Option 2: Environment variable (persistent, no token cost)
Set AGENT_TOOL_FALLBACK_ENCODING environment variable:
  Windows:  setx AGENT_TOOL_FALLBACK_ENCODING EUC-KR
  Linux:    export AGENT_TOOL_FALLBACK_ENCODING=EUC-KR  (add to ~/.bashrc)

### Option 3: CLI flag (per-session)
Start agent-tool with:
  agent-tool --fallback-encoding EUC-KR

Priority: CLI flag > environment variable > default (UTF-8).
These apply when chardet auto-detection fails (confidence < 50%).

## Supported encodings
UTF-8, UTF-8 BOM, EUC-KR, Shift_JIS, ISO-8859-1, UTF-16BE, UTF-16LE, and more.

## Warning messages
- "Encoding detection failed (low confidence)": chardet couldn't identify the encoding.
  → Add charset to .editorconfig or set --fallback-encoding.
- "Encoding detected as X (confidence: N%)": chardet is unsure about the result.
  → If text looks correct, no action needed. If garbled, add charset to .editorconfig.

## Disabling warnings
To suppress encoding warning messages:
  Use set_config with encoding_warnings = false`
}

func helpIndentation() string {
	return `# Indentation Guide

## How indentation detection works
Priority order:
1. .editorconfig 'indent_style' and 'indent_size'
2. File content analysis (first 100 lines)
3. Legacy protection: if .editorconfig says tabs but file uses spaces, spaces are preserved

## Smart indentation conversion
LLMs typically output spaces. agent-tool auto-converts to match the file's style:
- Spaces → Tabs (when file uses tabs)
- Tabs → Spaces (when file uses spaces)
- Spaces 2 → Spaces 4 (different indent sizes)

## Explicit override
The edit tool supports an 'indent_style' parameter:
- "tabs": Force tab indentation
- "spaces-2": Force 2-space indentation
- "spaces-4": Force 4-space indentation
- "spaces": Force 4-space indentation (default size)

## Setting up .editorconfig
  [*]
  indent_style = tab
  indent_size = 4

  [*.py]
  indent_style = space
  indent_size = 4

  [*.{yml,yaml}]
  indent_style = space
  indent_size = 2`
}

func helpTools() string {
	return `# Tool Reference

## edit
Replace text in a file with smart indentation and encoding preservation.
Parameters: file_path, old_string, new_string, replace_all, dry_run, indent_style

## read
Read a file with encoding auto-detection. Returns content with line numbers.
Supports negative offset to read from end (e.g. offset=-5 reads last 5 lines).
Parameters: file_path, offset (1-based, or negative for end-relative), limit

## write
Create or overwrite a file. Preserves encoding for existing files.
Parameters: file_path, content

## grep
Search file contents with regex. Encoding-aware.
Parameters: pattern, path, glob, ignore_case, max_results

## glob
Find files by pattern. Supports ** for recursive matching.
Use relative_paths=true to return paths relative to search directory (saves tokens).
Parameters: pattern, path, relative_paths

## listdir
List directory contents. Default: flat listing (one path per line, token-efficient).
Use flat=false for visual tree structure with connectors.
Use relative_paths=true to show root as '.' instead of full absolute path (saves tokens).
Parameters: path, max_depth, relative_paths, flat

## compress
Create zip or tar.gz archive.
Parameters: sources (array), output

## decompress
Extract zip or tar.gz archive. Includes Zip Slip and Zip Bomb protection.
Symlinks are skipped by default (security). Enable via set_config allow_symlinks=true.
Even when enabled, symlinks targeting outside the output directory are blocked.
Parameters: archive, output_dir

## backup
Create timestamped zip backup with exclude patterns.
Use dry_run=true to preview: shows included/excluded file counts, directory stats,
exclude pattern match counts, and largest files — without creating the archive.
Parameters: source, output_dir, excludes, dry_run

## convert_encoding
Convert a file's encoding to a different character set.
Supports: UTF-8, UTF-8-BOM, EUC-KR, Shift_JIS, ISO-8859-1, UTF-16, ASCII, Windows-1252, Big5, GB18030.
Parameters: file_path, to_encoding

## checksum
Compute file hash checksum. Reads raw bytes (no encoding conversion).
Parameters: file_path, algorithm (md5, sha1, sha256; default sha256)

## file_info
Returns detailed file metadata: size, encoding, line ending, indentation, line count.
Parameters: file_path

## diff
Compare two files and output unified diff. Encoding-aware.
Parameters: file_a, file_b, context_lines (default 3)

## patch
Apply unified diff patch to a file. Verifies context lines before applying.
Parameters: file_path, patch, dry_run

## delete
Delete a single file safely.
Safety: no directory deletion, no symlinks, no path traversal (..).
Use dry_run=true to preview what would be deleted.
Parameters: file_path, dry_run

## rename
Rename or move a file/directory. Uses os.Rename (atomic operation).
Fails if destination already exists.
Use dry_run=true to preview.
Parameters: old_path, new_path, dry_run

## sysinfo
Returns system information: OS, CPU cores, RAM, disk space, hostname, uptime.
Set duration_sec (1-20) to measure CPU usage over that period.
Parameters: duration_sec

## find_tools
Discover installed development tools on the system.
Returns paths and versions for compilers, build systems, and runtimes.
Searches env vars, PATH, and known installation directories.
Windows: also checks ~/bin, scoop shims, npm global. Unix: also checks ~/bin, ~/.local/bin, Homebrew.
Parameters: category (go, dotnet, node, python, java, rust, c_cpp, build, vcs, container, js_runtime, or all)

## proclist
List running processes with PID, name, command line arguments, and memory usage.
Sensitive data in command lines (passwords, tokens, Bearer) is automatically masked.
Parameters: filter (name search), port (find process using specific port)

## prockill
Kill, suspend, or resume a process by PID or port number.
Supports tree kill (process + all children), signal selection (kill/term/hup/int/stop/cont).
Use signal=stop to suspend and signal=cont to resume a process.
On Linux, can detect and handle zombie processes by signaling their parent.
Use dry_run=true to preview. Safety: refuses PID 0/1 and self.
Parameters: pid, port, signal, tree, include_zombies, dry_run

## procexec
Execute a command as a new process. Supports foreground, background, and suspended execution.
WARNING: Executes arbitrary commands on the host system.
Use suspended=true to start in suspended state (Windows: CREATE_SUSPENDED, Linux: SIGSTOP).
Use prockill with signal=cont to resume a suspended process.
Parameters: command, args, cwd, env, timeout_sec, background, suspended

## envvar
Read environment variables. Get a specific one by name, or list all with filter.
Sensitive values (PASSWORD, TOKEN, SECRET, KEY, etc.) are automatically masked.
Parameters: name (exact name), filter (partial name match)

## firewall
Read firewall rules (read-only). Supports iptables, nftables, firewalld on Linux; netsh on Windows.
May require elevated privileges (sudo) on Linux.
Parameters: filter (rule name or port)

## ssh
Execute commands on a remote server via SSH. Supports IPv4 and IPv6.
Supports password and key-based authentication (PEM, OpenSSH, and PuTTY PPK formats). SSH agent auto-used on Unix.
Sessions are pooled and reused (idle timeout: 30 min, max: 20 sessions).
Host key verification: strict (known_hosts required), tofu (trust on first use, default), none (insecure).
ProxyJump: use jump_host to connect through a bastion (e.g. reach IPv6-only servers via IPv4 bastion).
Parameters: host, port, user, password, key_file, passphrase, use_agent, command, disconnect, host_key_check, timeout_sec, jump_host, jump_port, jump_user, jump_password, jump_key_file, jump_passphrase

## sftp
Transfer files and manage remote filesystems over SSH (SFTP protocol).
Reuses SSH session pool — same authentication, session reuse, and idle timeout (30 min) as ssh tool.
Sync operations: upload (local→remote), download (remote→local), ls, stat, mkdir, rm, chmod, rename.
Async operations: upload_async, download_async (returns transfer_id), status (check progress), cancel.
Max transfer size: 2 GB. Recursive delete limited to 10,000 items. Dangerous paths (/, /home, /etc, etc.) protected.
Parameters: host, port, user, password, key_file, passphrase, use_agent, host_key_check,
  jump_host, jump_port, jump_user, jump_password, jump_key_file, jump_passphrase,
  operation, local_path, remote_path, recursive, mode, new_path, overwrite, transfer_id

## bash
Persistent shell sessions that maintain working directory, environment variables, and state across calls.
Sessions are pooled (max 5, idle timeout 30 min). Uses sentinel markers for output delimitation.
Platform: bash/sh on Unix, pwsh/git-bash/powershell/cmd on Windows (auto-detected, priority order).
Use disconnect=true to close a session.
Parameters: command, cwd (initial directory for new sessions), session_id (default: "default"), timeout_sec (default 120, max 600), disconnect

## webfetch
Fetch content from a URL and return it as text. HTML pages are automatically converted to Markdown.
ECH (Encrypted Client Hello) and DoH (DNS over HTTPS) enabled by default for privacy.
Cloud metadata SSRF protection (blocks 169.254.x.x, link-local). Private IPs allowed for local dev.
Default User-Agent mimics Chrome browser. Custom headers supported (User-Agent, Referer, etc.).
Supports HTTP and SOCKS5 proxies.
Parameters: url, headers, max_length (default 100000), timeout_sec (default 30, max 120), proxy_url, no_doh, no_ech, raw

## websearch
Search the web using Brave Search or Naver Search API.
Requires API keys via environment variables:
- BRAVE_SEARCH_API_KEY for Brave Search (English/global, default)
- NAVER_CLIENT_ID + NAVER_CLIENT_SECRET for Naver Search (Korean content)
Auto-selects engine based on configured keys (Brave preferred) if engine is not specified.
Parameters: query, engine (brave/naver), max_results (default 5, max 20), timeout_sec (default 15, max 30)

## download
Download a file from a URL and save it to disk. Supports binary and text files.
ECH and DoH enabled by default. Cloud metadata SSRF protection. HTTP and SOCKS5 proxy support.
Atomic file write (temp file + rename). Auto-creates parent directories.
Parameters: url, output_path, headers, overwrite, timeout_sec (default 60, max 600), max_size_mb (default 100, max 2048), proxy_url, no_doh, no_ech

## httpreq
Execute HTTP requests with any method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS).
Ideal for testing APIs, webhooks, and web services during development.
ECH and DoH enabled by default. Cloud metadata SSRF protection. HTTP and SOCKS5 proxy support.
DLP: POST/PUT/PATCH bodies are scanned for sensitive data (PEM keys, AWS keys, tokens, .env dumps) and blocked before transmission.
Response body is truncated at max_response_kb. Binary responses show Content-Type and size only.
Parameters: url, method, body, headers, content_type (default application/json), timeout_sec (default 30, max 120), max_response_kb (default 512, max 2048), proxy_url, no_doh, no_ech

## copy
Copy a file or directory. Supports recursive directory copying.
Uses atomic write (temp file + rename) and preserves file permissions.
Validates absolute paths and blocks path traversal (..).
Parameters: source, destination, overwrite (default false), dry_run (default false)

## mkdir
Create a directory. Creates parent directories by default (like mkdir -p).
Supports permission mode in octal (e.g. 0755, 0700) — applied on Unix/Linux.
Use dry_run=true to preview what would be created.
Parameters: path, recursive (default true), mode (octal, default 0755), dry_run

## multiread
Read multiple files in a single call to reduce API round-trips.
Each file is read with encoding auto-detection and line numbering.
Files are separated with headers. Errors on individual files don't stop processing.
Parameters: file_paths (array, max 50), offset (1-based, or negative for end-relative), limit

## regexreplace
Regex find-and-replace in files or across directories.
Supports capture groups ($1, $2, ${name}) in replacement strings.
Encoding-aware: preserves original file encoding. Skips binary files.
Atomic write for each modified file.
Parameters: pattern, replacement, path (file or directory), glob, ignore_case, dry_run, max_files (default 100)

## jsonquery
Query a JSON file using dot-notation paths without loading the entire file into context.
Supports nested keys (a.b.c), array indices ([0], [-1] for last), and wildcards ([*] for all elements).
Examples: "dependencies.react", "scripts.build", "items[0].name", "users[*].email".
Returns the matched value with its type. Objects and arrays are pretty-printed.
Parameters: file_path, query

## yamlquery
Query a YAML file using dot-notation paths (same syntax as jsonquery).
Supports nested keys, array indices, and wildcards.
Examples: "services.web.ports[0]", "spec.containers[*].image".
Parameters: file_path, query

## tomlquery
Query a TOML file using dot-notation paths (same syntax as jsonquery).
Supports nested keys, array indices, and wildcards.
Handles TOML-specific types: int64, datetime (RFC3339).
Examples: "dependencies.react", "tool.poetry.name", "servers[0].host".
Parameters: file_path, query

## portcheck
Check if a TCP port is open on a host. Tests connectivity with configurable timeout.
Returns OPEN/CLOSED status with response time or error details (refused, timeout, DNS failure).
Supports hostnames, IPv4, and IPv6 addresses.
Parameters: host, port (1-65535), timeout_sec (default 5, max 30)

## tlscheck
Check TLS certificate and connection details of a remote host.
Returns: Subject, Issuer, NotBefore, NotAfter, days until expiry, SANs, TLS version, cipher suite.
Parameters: host, port (default 443), timeout_sec (default 10, max 30)

## dnslookup
Look up DNS records for a hostname.
Supports record types: A, AAAA, MX, CNAME, TXT, NS, SOA.
Uses DNS over HTTPS (DoH) by default for privacy. Can fall back to system DNS.
Parameters: host, record_type (default A), use_doh (default true), doh_endpoint

## mysql
Execute SQL queries on a MySQL/MariaDB server.
SELECT/SHOW/DESCRIBE/EXPLAIN queries return results as formatted table.
Other queries (INSERT/UPDATE/DELETE) return affected rows and last insert ID.
Connection is opened and closed per call (no session pooling).
Parameters: host, port (default 3306), user, password, database, query, timeout_sec (default 30, max 120)

## redis
Execute Redis commands on a Redis server.
Supports any Redis command (GET, SET, HGETALL, etc.) via command + args.
Results are formatted by type (string, integer, array, nil).
Supports TLS connections. Connection is opened and closed per call.
Parameters: host, port (default 6379), password, db (default 0), command, args (array), timeout_sec (default 30, max 120), tls

## externalip
Returns your external (public) IP address.
Queries multiple IP detection services (ipify, ifconfig.me, icanhazip) with automatic fallback.
Useful for SSH configuration, firewall rules, or verifying VPN/proxy status.
No parameters required.

## sloc
Count source lines of code (SLOC) in a file or directory.
Returns per-language summary with file count, total lines, and blank lines.
Recognizes 70+ languages by file extension. Skips node_modules, .git, vendor, dist, build.
Parameters: path (file or directory), glob (filter pattern), max_depth, show_files, skip_blank

## debug
Interactive debugger using Debug Adapter Protocol (DAP).
Supports any language with a DAP-compatible adapter (dlv for Go, debugpy for Python, codelldb/lldb-dap for C/C++/Rust).
Uses a single tool with operation parameter for all debug actions.
Operations: launch, attach, set_breakpoints, continue, next, step_in, step_out, pause, threads, stack_trace, scopes, variables, evaluate, disconnect, status.
Session-based: launch/attach creates a session, subsequent operations use session_id.
Stepping operations (continue, next, step_in, step_out) block until a stopped event (breakpoint, step completion) or timeout.
Use operation=status to poll for events (output, state changes) between operations.
Parameters: session_id, operation, adapter_command, adapter_args, address, launch_args (JSON),
  source_path, breakpoints (JSON array), thread_id, frame_id, variables_reference,
  expression, context, timeout_sec

## analyze
Static binary analysis tool with 20 operations:
- disassemble: x86/x64/ARM/ARM64 disassembly (stop_at_ret for function-scoped)
- pe_info: PE header parsing with RWX section warnings
- elf_info: ELF header/sections/segments/symbols with RWX warnings
- macho_info: Mach-O header/segments/sections/symbols (fat binary support)
- strings: Extract printable strings (ASCII and UTF-8)
- hexdump: Hex + ASCII dump of file regions
- pattern_search: Hex byte pattern matching with ?? wildcards (shows section names)
- entropy: Shannon entropy per section (detects packed/encrypted regions)
- bin_diff: Two-file byte comparison
- resource_info: PE resource directory and version info extraction
- imphash: PE import hash (MD5) for malware classification
- rich_header: PE Rich header -- build tool fingerprinting
- overlay_detect: Detect data appended after last section
- dwarf_info: DWARF debug info (compilation units, functions, types)
- xref: Find code references to target address (with type summary)
- function_at: Find function boundaries (.pdata or heuristic)
- call_graph: Static call graph from root function
- follow_ptr: Follow pointer chain with symbol annotation (PE)
- rtti_dump: Parse MSVC RTTI from vtable (class name + base classes)
- struct_layout: Dump memory as structured layout with annotations (PE)
Parameters: operation, file_path, offset, count, mode, arch (x86/arm),
  base_addr, min_length, max_results, length, section, pattern, file_path_b,
  va, target_va, stop_at_ret
Use topic='analyze' for detailed guide with examples.

## set_config
Change agent-tool runtime configuration.
Supports: fallback_encoding, encoding_warnings, max_file_size_mb, allow_symlinks, workspace.
SSRF policy: allow_http_private (default false), allow_mysql_private, allow_redis_private, allow_ssh_private (default true).
Network: enable_doh (DNS over HTTPS, default true), enable_ech (Encrypted Client Hello, default true).
Call with no arguments to view current config.
Parameters: fallback_encoding, encoding_warnings, max_file_size_mb, allow_symlinks, workspace, allow_http_private, allow_mysql_private, allow_redis_private, allow_ssh_private, enable_doh, enable_ech`
}

func helpAnalyze() string {
	return `# Static Binary Analysis Tool

## Overview
The analyze tool provides static binary analysis without executing the target file.
Uses a single tool with operation parameter (like debug/sftp).
Pure Go implementation — no CGO, no external dependencies for disassembly.

## Operations

### disassemble
Disassemble machine code. Supports x86 (16/32/64-bit) and ARM (32/64-bit).
  analyze(operation="disassemble", file_path="/path/to/binary",
          offset=4096, count=50, mode=64, arch="x86", base_addr="0x140001000")

  # ARM64 example:
  analyze(operation="disassemble", file_path="/path/to/arm_binary",
          offset=0, count=50, mode=64, arch="arm")

  Parameters:
    arch: CPU architecture -- "x86" (default) or "arm"
    offset: Byte offset in the file to start from (default: 0)
    va: Virtual address (hex) -- auto-converts to file offset using PE headers.
        Also auto-sets base_addr to ImageBase and mode from PE Machine field.
        Example: va="0x140001000" (PE only)
    count: Number of instructions to decode (default: 50, max: 600)
    stop_at_ret: Stop at function return (RET/RETF + padding/prologue boundary)
    mode: CPU mode -- x86: 16/32/64, arm: 32/64 (default: 64)
    base_addr: Base address mapped to file offset 0 (hex string, default: "0").
               Displayed address = base_addr + offset + position.
               For PE files, use ImageBase (e.g. 0x140000000), not section VA.

  When using va=, disassembly auto-stops at the function boundary (via .pdata)
  if available, preventing disassembly into the next function.
  Import/export symbols are annotated inline (e.g. "call [rip+0x1234]  ; CreateFileW").

  Output: address: hex_bytes    assembly  [; symbol]
  x86 uses Intel syntax. Failed decodes show "db 0xNN" / ".word" and skip.

### pe_info
Parse PE (Portable Executable) headers -- Windows EXE, DLL, .node files.
  analyze(operation="pe_info", file_path="/path/to/file.dll")
  analyze(operation="pe_info", file_path="/path/to/file.dll", section=".text")

  Output includes:
    - Machine type, image base, entry point, number of sections
    - Section table: Name, VirtualAddress, VirtualSize, RawOffset, RawSize, Permissions
    - Section permissions (R/W/X, CODE/DATA) with ⚠ W+X warnings for suspicious sections
    - Imports: grouped by DLL with IAT slot VAs (for xref cross-referencing)
    - Exports: function names with RVAs (if present)
    - RVA->FileOffset conversion table for each section

  Parameters:
    section: Filter to show only a specific section (e.g. ".text", ".rdata")
             Use section=".pdata" to show all RUNTIME_FUNCTION entries as a
             function table with Start VA, End VA, Size, and Unwind RVA.
             Use section=".text" to auto-disassemble from the entry point.
    rva: Convert an RVA to file offset (hex string, e.g. "0x36A20")

  Use the RVA->FileOffset table to convert runtime addresses to file offsets
  for targeted disassembly or hexdump.

### elf_info
Parse ELF (Executable and Linkable Format) binaries — Linux shared objects, executables.
  analyze(operation="elf_info", file_path="/path/to/binary")

  Output includes:
    - Class, OS/ABI, type, machine, entry point
    - Section table with permissions and ⚠ W+X warnings
    - Program headers (segments) with R/W/X flags and ⚠ W+X warnings
    - Imported libraries and symbols
    - Exported (dynamic) symbols

  Parameters:
    section: Filter to show only a specific section

### macho_info
Parse Mach-O binaries — macOS/iOS executables, dylibs, frameworks.
  analyze(operation="macho_info", file_path="/path/to/binary")

  Output includes:
    - CPU type, binary type, flags (PIE, DYLDLINK, etc.)
    - Load commands
    - Section table
    - Segments with MaxProt/InitProt and ⚠ W+X warnings
    - Imported libraries and symbols

  Supports Universal (Fat) binaries — shows all architectures.

  Parameters:
    section: Filter to show only a specific section

### strings
Extract printable strings from a binary file.
  analyze(operation="strings", file_path="/path/to/binary",
          min_length=6, max_results=100)

  Two extraction modes:
    encoding="ascii" (default): ASCII strings (bytes 0x20-0x7E)
    encoding="utf8": UTF-8 strings (multi-byte aware, filters non-printable runes)

  Parameters:
    min_length: Minimum string length (default: 4)
    max_results: Maximum number of results (default: 500, max: 2000)
    encoding: String encoding -- "ascii" (default) or "utf8"

  Output: offset: "string content"
  For PE files, VA is shown alongside file offset: offset (VA): "string"

### hexdump
Display raw bytes in hex + ASCII format.
  analyze(operation="hexdump", file_path="/path/to/binary",
          offset=8192, length=512)

  Standard hexdump format: offset  hex hex hex ... |ASCII...|
  16 bytes per line. Non-printable bytes shown as '.' in ASCII column.

  Parameters:
    offset: Byte offset to start from (default: 0)
    length: Number of bytes to dump (default: 256, max: 4096)

### pattern_search
Search for hex byte patterns with wildcard support.
  analyze(operation="pattern_search", file_path="/path/to/binary",
          pattern="4D 5A ?? ?? 50 45")

  Pattern format: hex bytes separated by spaces, "??" for any byte wildcard.
  Example: "48 89 5C 24 ??" matches MOV [rsp+??], rbx with any offset.

  Parameters:
    pattern: Hex byte pattern (e.g. "4D 5A ?? ?? 50 45")
    max_results: Maximum matches to return (default: 100, max: 500)

  For PE files, VA is shown alongside file offset in results.
  Uses chunked file reading with overlap -- handles multi-GB files efficiently.

### entropy
Calculate Shannon entropy per section.
  analyze(operation="entropy", file_path="/path/to/binary")

  Shows overall file entropy (0-8 bits/byte) and per-section breakdown.
  Auto-detects PE, ELF, and Mach-O formats for section boundaries.
  Falls back to 4KB block-based analysis for unknown formats.

  Entropy interpretation:
    < 1.0: Very low (padding, zeroes)
    1-3: Low (structured data, headers)
    3-5: Medium (code, text)
    5-7: High (compiled code)
    > 7: Very high (compressed, encrypted, or random data)

  High-entropy sections in otherwise normal binaries suggest packing or encryption.

### bin_diff
Compare two binary files byte-by-byte and report differences.
  analyze(operation="bin_diff", file_path="/path/to/file_a",
          file_path_b="/path/to/file_b", max_results=50)

  Reports:
    - File sizes and size difference
    - Per-byte differences: offset, value in file A, value in file B
    - Total count of differing bytes

  Useful for: finding patched bytes, comparing versions, detecting tampering.

  Parameters:
    file_path_b: Second file to compare (required for bin_diff)
    max_results: Maximum differences to show (default: 100, max: 500)

### resource_info
Extract PE resource directory and version information.
  analyze(operation="resource_info", file_path="/path/to/file.exe")

  Output includes:
    - Resource type counts (RT_ICON, RT_VERSION, RT_MANIFEST, etc.)
    - Individual entries with type, ID, language, size
    - Version strings (CompanyName, ProductName, FileVersion, etc.)

### imphash
Compute the PE import hash (MD5 of normalized import table).
  analyze(operation="imphash", file_path="/path/to/file.exe")

  Imphash is a standard for malware classification — binaries built from
  the same source share the same imphash. Used by VirusTotal, MISP, Mandiant.

  Output: hash value + first 20 normalized imports (dll.function format).

### rich_header
Parse the PE Rich header (undocumented Microsoft build tool fingerprint).
  analyze(operation="rich_header", file_path="/path/to/file.exe")

  Shows which compiler/linker/assembler versions built each object file.
  Useful for attribution and build environment identification.
  Includes Rich header MD5 hash for clustering.

### overlay_detect
Check for data appended after the last section of a binary.
  analyze(operation="overlay_detect", file_path="/path/to/file.exe")

  Detects overlays in PE, ELF, and Mach-O files.
  Reports overlay size, percentage, hex preview, and signature identification
  (ZIP, GZIP, RAR, 7z, embedded PE/ELF/Mach-O).

  Common in: packed executables, droppers, self-extracting archives.

### dwarf_info
Extract DWARF debug information from PE, ELF, or Mach-O binaries.
  analyze(operation="dwarf_info", file_path="/path/to/binary")

  Output includes:
    - Compilation units (source files)
    - Functions with addresses (low PC / high PC)
    - Variable/parameter and type counts
    - "Binary appears stripped" if no DWARF data found

### xref
Find all code locations that reference a target address (PE only).
  analyze(operation="xref", file_path="/path/to/binary.exe",
          target_va="0x140001000")

  Scans executable sections for instruction patterns that reference the target:
    x64: E8/E9 (CALL/JMP relative), 0F 8x (Jcc), LEA [rip+disp32],
         FF 15/25 (indirect CALL/JMP [rip+disp32]), MOV [rip+disp32]
    x86: E8/E9 (relative), 0F 8x (Jcc), 68 imm32 (PUSH absolute)

  Parameters:
    target_va: Virtual address to find references to (hex, required)
    max_results: Maximum results (default: 200, max: 1000)

  Auto-detects x86 vs x64 from PE Machine field.

### function_at
Find function boundaries in PE files.
  analyze(operation="function_at", file_path="/path/to/binary.exe",
          va="0x140001000")

  Detection methods (automatic):
  1. .pdata (Exception Table) -- reliable, x64 PE with unwind info
  2. Heuristic (prologue/epilogue pattern scan) -- fallback for x86 PE,
     stripped x64, or binaries without .pdata

  Also auto-disassembles the function (use count to control instruction limit).

  Parameters:
    va: Virtual address inside the function (hex, required)
    count: Max instructions to disassemble (default: 50, max: 200)

  Heuristic scans for prologue patterns (push rbp/ebp; mov rbp/ebp, rsp/esp)
  and epilogue (ret + int3/nop padding). Results are marked with confidence level.
  Returns function start, end, size, and disassembly.

### call_graph
Build a static call graph from a root function (x64 PE only).
  analyze(operation="call_graph", file_path="/path/to/binary.exe",
          va="0x140001000")

  Uses .pdata for function boundaries and scans CALL (E8 rel32) instructions.
  BFS traversal from the root function, showing:
  - Callers: functions that call the root (1 level, reverse scan)
  - Callees: functions called by the root (tree format, configurable depth)

  Parameters:
    va: Root function address (hex, required)
    count: Max depth (default: 2, max: 5)
    max_results: Max nodes to visit (default: 200, max: 500)

  Only includes callees that land on .pdata function starts (filters false positives).
  Cycle detection marks revisited nodes as "(already shown)".

### follow_ptr
Follow a chain of pointers in a PE file with symbol/section annotation.
  analyze(operation="follow_ptr", file_path="/path/to/binary.exe",
          va="0x140050000", count=6)

  Reads pointer-sized values starting at VA, follows the chain, and annotates
  each step with symbol names or section info. Stops on null, unmapped, or depth limit.

  Parameters:
    va: Starting virtual address (hex, required)
    count: Maximum depth (default: 4, max: 10)

  Output: [0] 0x140050000 (.rdata) -> 0x140060ABC (MyClass::vtable)

### rtti_dump
Parse MSVC RTTI (Run-Time Type Information) from a vtable address.
  analyze(operation="rtti_dump", file_path="/path/to/binary.exe",
          va="0x140050000")

  Reads vtable[-4] (x86) or vtable[-8] (x64) to find CompleteObjectLocator,
  then parses TypeDescriptor (class name) and ClassHierarchyDescriptor (base classes).

  Parameters:
    va: Vtable virtual address (hex, required)

  Output: class name (mangled), base class list with displacements.
  Auto-detects x86 vs x64 from PE Machine field.

### struct_layout
Dump a memory region as a structured layout with pointer-sized slots.
  analyze(operation="struct_layout", file_path="/path/to/binary.exe",
          va="0x140050000", length=128)

  Each slot is annotated: symbol name, [code]/[data]/[rdata] section, or [null].
  Useful for inspecting vtables, object layouts, and data structures.

  Parameters:
    va: Starting virtual address (hex, required)
    length: Number of bytes to dump (default: 64, max: 512)

## Typical Workflow

1. pe_info/elf_info/macho_info -- Get section layout, check for W+X sections
2. entropy -- Identify packed/encrypted sections (entropy > 7.0)
3. overlay_detect -- Check for appended payloads
4. imphash -- Classify by import table fingerprint
5. rich_header -- Identify build tools (PE only)
6. strings -- Find interesting strings, API names, error messages
7. pattern_search -- Locate specific byte sequences (signatures, opcodes)
8. hexdump -- Examine specific data regions at file offsets
9. disassemble -- Decode machine code (use va= for PE virtual addresses)
10. function_at -- Find function boundaries (.pdata or heuristic fallback)
11. xref -- Find all call/jump/data references to an address (PE)
12. call_graph -- Build static call graph from a root function (x64 PE)
13. follow_ptr -- Follow pointer chains (vtable inspection, data structure traversal)
14. rtti_dump -- Parse MSVC RTTI from vtable (identify C++ class hierarchy)
15. struct_layout -- Dump memory as structured layout (vtable, object layout analysis)
16. dwarf_info -- Extract debug symbols and function names
17. bin_diff -- Compare original vs patched versions

### Example: Analyzing a DLL
  # Step 1: Get PE layout
  analyze(operation="pe_info", file_path="C:/path/to/target.dll")
  # Note: .text section at RawOffset=0x400, .rdata at RawOffset=0x27C00

  # Step 2: Find interesting strings
  analyze(operation="strings", file_path="C:/path/to/target.dll", min_length=8)

  # Step 3: Disassemble code section
  analyze(operation="disassemble", file_path="C:/path/to/target.dll",
          offset=1024, count=100, mode=64, base_addr="0x180001000")

  # Step 4: Examine data at specific offset
  analyze(operation="hexdump", file_path="C:/path/to/target.dll",
          offset=163840, length=256)

## Notes
- File size limit follows max_file_size_mb setting (default 50 MB)
- Symlinks are rejected for security
- x86 disassembly: golang.org/x/arch/x86/x86asm (Intel syntax)
- ARM disassembly: golang.org/x/arch/arm/armasm + arm64/arm64asm
- Binary parsing: Go standard library (debug/pe, debug/elf, debug/macho, debug/dwarf)
- All 14 operations are read-only — the target file is never modified
- Zero external dependencies beyond golang.org/x/arch`
}

func helpDebug() string {
	return `# Debug Tool Guide (DAP)

## Overview
The debug tool provides interactive debugging via the Debug Adapter Protocol (DAP).
It works with any language that has a DAP-compatible debug adapter.

## Tested Adapters
- Go: dlv (Delve) — fully tested
- Python: debugpy — fully tested
- C/C++: codelldb (recommended, open source) — LLDB-based, reads PDB on Windows
- C/C++: vsdbg — UNSTABLE. Handshake signing works, but vsdbg enforces a
  secondary runtime license check that blocks non-VS Code clients.
  Use codelldb instead unless you specifically need MSVC-native debugging.

## Workflow

### 1. Launch → 2. Set breakpoints → 3. Continue → 4. Inspect → 5. Step → 6. Disconnect

  launch → set_breakpoints → continue (blocks until hit) →
  stack_trace → scopes → variables → evaluate →
  next/step_in/step_out → continue → ... → disconnect

## Adapter Recipes (copy-paste ready)

### Go (dlv)
  Install: go install github.com/go-delve/delve/cmd/dlv@latest

  debug(operation="launch",
        adapter_command="dlv", adapter_args=["dap"],
        launch_args='{"program":"./","mode":"debug","cwd":"/path/to/project"}')

  With registers:
  launch_args='{"program":"./","mode":"debug","cwd":"/path/to/project","showRegisters":true}'

  IMPORTANT: "program" should be "./" (relative) with "cwd" set to the project directory.
  Using an absolute path for "program" may fail if it points to a directory.

### Python (debugpy)
  Install: pip install debugpy

  Stdio mode (recommended — single step):
  debug(operation="launch",
        adapter_command="python", adapter_args=["-m", "debugpy.adapter"],
        launch_args='{"program":"/path/to/script.py","cwd":"/path/to/project","console":"internalConsole"}')

  TCP mode (alternative — two steps):
  Step 1: Run in terminal: python -m debugpy.adapter --host 127.0.0.1 --port 5679
  Step 2: debug(operation="attach", address="127.0.0.1:5679",
        launch_args='{"program":"/path/to/script.py","request":"launch","console":"internalConsole"}')

### C/C++ (codelldb — recommended)
  Install: Download from https://github.com/vadimcn/codelldb/releases
  Or install the CodeLLDB VS Code extension.

  debug(operation="launch",
        adapter_command="/path/to/codelldb",
        adapter_args=["--port", "0"],
        launch_args='{"type":"lldb","program":"/path/to/binary","cwd":"/path/to/project","stopOnEntry":true}')

### C/C++ (vsdbg — UNSTABLE, requires VS Code C++ extension installed)
  WARNING: vsdbg may reject connections with "C/C++ Debugging is supported only
  in Microsoft versions of VS Code" even after successful handshake signing.
  This is a secondary license check beyond the handshake. Use codelldb instead.

  vsdbg requires adapterID="cppvsdbg" and clientID="vscode".
  Set "type":"cppvsdbg" and "__clientID":"vscode" in launch_args.

  debug(operation="launch",
        adapter_command="/path/to/vsdbg.exe",
        adapter_args=["--interpreter=vscode"],
        launch_args='{"type":"cppvsdbg","__clientID":"vscode","__clientName":"Visual Studio Code","program":"/path/to/binary.exe","cwd":"/path/to/project","console":"internalConsole","stopAtEntry":true}')

  vsdbg is typically located at:
  Windows: %USERPROFILE%/.vscode/extensions/ms-vscode.cpptools-*/debugAdapters/vsdbg/bin/vsdbg.exe
  Linux/Mac: ~/.vscode/extensions/ms-vscode.cpptools-*/debugAdapters/vsdbg/bin/vsdbg

## Key Operations Reference

  Core:
    set_breakpoints: source_path + breakpoints='[{"line":42},{"line":100,"condition":"x > 5"}]'
    continue/next/step_in/step_out: blocks until stopped (timeout_sec to limit wait)
    stack_trace: returns frame IDs → use frame_id for scopes/evaluate
    scopes: returns scope names + variablesReference IDs → use for variables
    variables: returns variable names, values, and nested references
    evaluate: expression evaluation with context (repl/watch/hover)
    threads: list all threads/goroutines
    status: session state + recent events (non-blocking)
    disconnect: end session and clean up

  Breakpoints:
    set_function_breakpoints: breakpoints='[{"name":"main.Run"}]'
    set_exception_breakpoints: filters='["raised","uncaught"]'
    set_data_breakpoints: breakpoints='[{"dataId":"...","accessType":"write"}]'
    data_breakpoint_info: query if data breakpoint can be set (name + variables_reference)
    set_instruction_breakpoints: breakpoints='[{"instructionReference":"0x4000"}]'

  Execution control:
    step_back / reverse_continue: reverse debugging (adapter must support)
    restart_frame: restart from a stack frame (frame_id)
    goto: jump to a target (target_id from goto_targets)
    goto_targets: list possible jump targets (source_path + line)
    step_in_targets: list possible step-in targets (frame_id)
    pause: suspend execution
    terminate: graceful termination (debuggee handles it)
    restart: restart the debug session

  Modification:
    set_variable: change variable value (variables_reference + name + value)
    set_expression: change expression value (expression + value + frame_id)

  Memory / disassembly:
    disassemble: disassemble from memory_reference (count = instruction count)
    read_memory: read bytes from memory_reference (count = byte count, returns base64)
    write_memory: write base64 data to memory_reference

  Info:
    modules: loaded modules/libraries (with symbol status)
    resolve_address: map address to module+offset (memory_reference='0x7ffe5488')
    loaded_sources: all loaded source files
    source: get source code by source_reference
    exception_info: current exception details (thread_id)
    completions: auto-completion suggestions (text + frame_id)
    cancel: cancel a pending request (request_id)
    terminate_threads: terminate specific threads (thread_ids='[1,2]')

## Adapter-Specific Notes

### AdapterID / "type" field
  Some adapters (vsdbg) require a specific adapterID in the DAP initialize handshake.
  If launch_args contains "type", that value is used as adapterID.
  Otherwise, the adapter binary filename (without extension) is used.
  If initialize fails, try adding "type" to launch_args with the adapter's expected ID.

### Client ID / Client Name
  Some adapters check clientID for licensing (vsdbg requires "vscode").
  Use the dedicated client_id and client_name parameters for common overrides.
  For advanced cases, __ (double underscore) prefixed keys in launch_args are
  meta fields consumed by this tool and stripped before sending to the adapter.
  Example: "__clientID":"vscode" in launch_args has the same effect as client_id="vscode".
  Priority: dedicated parameter > __ meta field > default ("agent-tool").

### Registers
  Registers are exposed through scopes → variables, NOT a separate operation.
  The adapter must include a "Registers" scope in the scopes response.
  - dlv: set "showRegisters":true in launch_args
  - codelldb/lldb-dap: registers shown by default
  - debugpy: not applicable (Python has no CPU registers)

### Features vary by adapter
  Each adapter supports different launch_args options and capabilities.
  If a feature seems missing (no registers, no conditional breakpoints, etc.),
  it's likely an adapter configuration issue — NOT a tool limitation.
  Search "<adapter name> DAP launch configuration" to find available options.

### Release Builds and Debugging
  Optimized/release builds can make debugging unreliable:
  - Variables may show <optimized out> or wrong values
  - set_variable may report success but not actually change the value
  - Lines may execute out of order or be skipped
  - Stack frames may be missing

  If you see these symptoms, rebuild with debug/unoptimized settings.
  Most languages and build systems have a "debug" vs "release" mode —
  always use debug mode when you need reliable variable inspection.

### Capabilities
  Use operation=status after launch to see which features the adapter supports.
  Unsupported operations will return an error — this is normal, not a bug.
  Example: dlv supports disassemble but not modules; debugpy supports modules but not disassemble.

### Breakpoint Timing
  Set breakpoints AFTER launch but BEFORE the first continue.
  The tool sends configurationDone automatically on the first continue.

## Using Other Adapters
  This tool is a standard DAP client. However, some adapters have non-standard
  quirks (custom adapterID requirements, extra handshake steps, adapter-specific
  launch_args fields). The recipes above document known quirks for tested adapters.

  For unlisted adapters:
  1. Search for "<language> DAP debug adapter" to find the adapter
  2. Check the adapter's docs for launch configuration — especially:
     - stdio vs TCP mode
     - Required launch_args fields (program, cwd, request, etc.)
     - Whether "type" must be set to a specific value (e.g. "cppvsdbg" for vsdbg)
  3. If initialize fails with a vague error, the most common cause is a wrong
     adapterID. Try setting "type" in launch_args to the value the adapter expects.
  4. If launch succeeds but debugging doesn't start, check operation=status for
     error events — some adapters have license restrictions (e.g. vsdbg).

## Tips
- If timeout occurs, use operation=status to check state and poll events
- Variables use reference IDs — get them from scopes response
- References are only valid while stopped; they reset on continue
- Max 5 concurrent debug sessions (oldest evicted at capacity)
- Sessions auto-expire after 30 minutes of inactivity
- Always disconnect when done to clean up adapter processes

## Debugging Tips for Specific Scenarios

### Node.js under codelldb (LLDB)
  When debugging Node.js scripts under codelldb, async operations (setTimeout,
  setImmediate, Promise callbacks) may NOT execute — Node's event loop doesn't
  tick properly under LLDB's stdio capture.
  Workaround: Use synchronous scripts only. Replace async patterns with sync
  equivalents (e.g., require() instead of dynamic import, synchronous loops
  instead of setTimeout).

### LLDB commands via evaluate
  codelldb supports LLDB native commands through evaluate with context="repl".
  Example: evaluate(expression="breakpoint set -a 0x7470", context="repl")
  These may return empty "Result: " strings but still execute successfully.
  Use "breakpoint list" to verify breakpoints were set.
  This is useful for instruction-level breakpoints when set_instruction_breakpoints
  fails (some adapters have parsing issues with hex addresses).

### vsdbg handshake
  vsdbg requires a proprietary handshake: it sends a reverse request with a
  challenge value, and the client must sign it. This tool handles the handshake
  automatically using a built-in signing algorithm. No external dependencies needed.
  Note: vsdbg may still enforce additional license checks beyond the handshake
  that restrict usage to VS Code environments.

### Reading native code / DLL internals
  Use codelldb with read_memory and disassemble for low-level inspection.
  For native addon analysis (e.g., .node files), load them in a host process
  (Node.js for .node files) and set instruction breakpoints at known RVAs.
  PE image base for DLLs is typically 0x180000000 — add the RVA offset to
  compute the runtime address for breakpoints.`
}

func helpTroubleshooting() string {
	return `# Troubleshooting

## Garbled text / encoding issues
Symptom: Korean, Japanese, or other non-ASCII text appears as garbage characters.

Cause: The file is encoded in EUC-KR, Shift-JIS, etc., but chardet couldn't detect it
(common with short files or files with little non-ASCII content).

Solutions (pick one):
1. Add to .editorconfig:
   [*]
   charset = euc-kr

2. Restart agent-tool with --fallback-encoding:
   agent-tool --fallback-encoding EUC-KR

## Indentation mismatch
Symptom: File uses tabs but edit introduces spaces (or vice versa).

Solutions:
1. Add .editorconfig with indent_style = tab
2. Use the edit tool's indent_style parameter: "tabs" or "spaces-4"

## old_string not found
Cause: The text you're trying to match doesn't exist exactly in the file.
Common reasons:
- Indentation differs (tabs vs spaces) — agent-tool handles this automatically
- Line endings differ (CRLF vs LF) — agent-tool normalizes these
- Invisible characters or encoding differences
- The text was already changed

## File encoding changed after edit
This shouldn't happen — agent-tool preserves the original encoding.
If it does, check:
1. Is .editorconfig charset set correctly?
2. Was the file originally in the expected encoding?
3. Report as a bug if encoding changes unexpectedly.

## Current server configuration
- Fallback encoding: ` + common.GetFallbackEncoding() + `
- Encoding warnings: ` + fmt.Sprintf("%v", common.GetEncodingWarnings()) + `
- Max file size: ` + fmt.Sprintf("%d MB", common.GetMaxFileSize()/(1024*1024)) + `
- Allow symlinks: ` + fmt.Sprintf("%v", common.GetAllowSymlinks()) + `
- Use set_config to change at runtime, or --fallback-encoding <CHARSET> at startup`
}

func helpMemtool() string {
	return `# Memory Tool (memtool)

Process memory tool for reverse engineering and game hacking.
CheatEngine-style: search, filter, write, pointer scan, struct search, diff.

## Platform Support
- Windows: OpenProcess + ReadProcessMemory/WriteProcessMemory + VirtualQueryEx
- Linux: /proc/pid/maps + /proc/pid/mem (read/write)
- macOS: Not supported (SIP)

## Operations

### regions - List memory regions
  memtool(operation="regions", pid=1234)
  memtool(operation="regions", pid=1234, protection="rw")

### search - Initial value scan (creates session)
  memtool(operation="search", pid=1234, value_type="int32", value="100")
  memtool(operation="search", pid=1234, value_type="bytes", value="4D 5A 90 00")
  memtool(operation="search", pid=1234, value_type="int32")  # unknown initial value
  Omit 'value' for unknown initial value scan — takes a full snapshot and
  lets you filter by changed/unchanged/increased/decreased.

### filter - Narrow matches (requires session_id)
  memtool(operation="filter", session_id="abc", filter_type="decreased")
  memtool(operation="filter", session_id="abc", filter_type="exact", value="95")
  Types: exact, changed, unchanged, increased, decreased

### undo - Restore previous filter state
  memtool(operation="undo", session_id="abc")

### read - Hex dump at address
  memtool(operation="read", pid=1234, address="0x7FF6A1B20000", length=128)

### write - Modify memory at address
  memtool(operation="write", pid=1234, address="0x...", value_type="int32", value="999")
  memtool(operation="write", pid=1234, address="0x...", value_type="bytes", value="90 90 90 90")

### disasm - Disassemble live process memory
  memtool(operation="disasm", pid=1234, address="0x7FF6A1B20000")
  memtool(operation="disasm", pid=1234, address="0x...", count=100, arch="x86", mode=64)
  memtool(operation="disasm", pid=1234, address="0x...", arch="arm", mode=64)
  Reads memory from the process and disassembles in-place.
  Uses the same disassembly engine as the analyze tool (x86/x64/ARM/ARM64).

### struct_search - Multi-field pattern search
  memtool(operation="struct_search", pid=1234,
	struct_pattern='[{"offset":0,"type":"int32","value":"100"},{"offset":4,"type":"int32","value":"50"}]')

### pointer_scan - Find pointer chains to an address
  memtool(operation="pointer_scan", pid=1234, address="0x...", max_depth=3, max_offset=4096)

### diff - Compare memory snapshots
  memtool(operation="diff", pid=1234)             # take first snapshot
  memtool(operation="diff", session_id="abc")      # compare with current

### info / close - Session management
  memtool(operation="info", session_id="abc")
  memtool(operation="close", session_id="abc")

## CheatEngine Workflow

### Known value:
  1. search(pid, value_type="int32", value="100") -> session, N matches
  2. [value changes] -> filter(session, filter_type="decreased")
  3. [value changes] -> filter(session, filter_type="exact", value="95")
  4. info(session) -> addresses + current values
  5. write(pid, address, value_type="int32", value="999") -> modify
  6. close(session)

### Unknown initial value:
  1. search(pid, value_type="int32") -> session (snapshot taken)
  2. [value changes] -> filter(session, filter_type="changed") -> N matches
  3. [value stable]  -> filter(session, filter_type="unchanged")
  4. [value changes] -> filter(session, filter_type="decreased")
  5. info(session) -> narrowed addresses
  6. write + close

## Session/Performance
  - Max 3 sessions (oldest evicted), 10min idle timeout
  - Hybrid storage: in-memory up to 10M matches, auto disk-backed beyond (up to 100M)
  - Parallel search (multi-core), batched filter reads (64KB groups)
  - Disk-backed snapshots for diff (handles multi-GB processes)
  - Undo stack: up to 5 levels

## Permissions
  - Windows: may require Administrator (OpenProcess)
  - Linux: same-user or root, or CAP_SYS_PTRACE`
}

func helpWintool() string {
	return `# wintool — Windows GUI Automation

Windows-only tool for finding, inspecting, and controlling windows.
macOS and Linux are not supported.

## Operations

### Discovery
  - list: Enumerate all top-level windows (HWND, PID, title, class, rect, visible)
    Supports filters: title, class, pid
  - find: Search windows by title/class/PID (at least one required)
  - tree: Show child window/control hierarchy of a specific window
  - inspect: Detailed info (styles, rect, client area, children count)

### Observation
  - screenshot: Capture a window as base64 PNG (works even if occluded)
    Uses PrintWindow (PW_RENDERFULLCONTENT), falls back to BitBlt
    Max resolution: 4096x4096. Returns data:image/png;base64,...
  - gettext: Read text from a window/control via WM_GETTEXT

### Interaction
  - settext: Set text on a window/control via WM_SETTEXT
  - click: Click at client-relative coordinates (left/right/middle)
  - type: Send keyboard characters via WM_CHAR
  - send: Raw SendMessage/PostMessage with custom msg/wParam/lParam
  - close: Send WM_CLOSE to a window
  - focus: Bring window to foreground (SetForegroundWindow)
  - show: Change window state (show/hide/minimize/maximize/restore)
  - move: Move and/or resize a window

## Workflow Examples

### Find and screenshot a window:
  1. list (or find title="Notepad") -> get HWND (e.g. 0x1A2B3C)
  2. screenshot(hwnd="0x1A2B3C") -> base64 PNG (agent can "see" it)
  3. tree(hwnd="0x1A2B3C") -> find Edit control HWND
  4. gettext(hwnd=edit_hwnd) -> read current text

### Automate a GUI application:
  1. find(title="MyApp") -> HWND
  2. tree -> find button/edit controls
  3. settext(hwnd=edit_ctrl, text="input value")
  4. click(hwnd=button_ctrl, x=10, y=10) -> click the button
  5. screenshot -> verify result

### Low-level message control:
  send(hwnd, msg=0x0111, wparam=button_id) -> WM_COMMAND
  send(hwnd, msg=0x0010) -> WM_CLOSE

## Notes
  - HWND is specified as hex string: "0x1A2B3C" or "1A2B3C"
  - Coordinates for click are client-relative (not screen coordinates)
  - SetForegroundWindow may fail if agent-tool is not the foreground process
  - screenshot returns base64-encoded PNG suitable for multimodal AI analysis`
}
