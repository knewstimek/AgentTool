# agent-tool

[한국어](README.ko.md)

<a href="https://glama.ai/mcp/servers/knewstimek/agent-tool">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/knewstimek/agent-tool/badge" alt="agent-tool MCP server" />
</a>

MCP (Model Context Protocol) tool server for AI coding agents.

## Why?

Built-in tools in AI coding agents (Claude Code, Cursor, Codex, etc.) have known limitations:

- **Tab indentation breaks**: LLMs output spaces, but your project uses tabs. The built-in Edit tool writes spaces as-is, corrupting your indentation style.
- **Encoding corruption**: Editing EUC-KR, Shift-JIS, or GB18030 files silently converts them to UTF-8, breaking legacy projects.
- **Too many separate tools**: Making the agent find, install, and configure Redis CLI, MySQL client, SSH client, etc. is tedious and error-prone. agent-tool bundles 50 tools into a single binary -- one install, everything works.
- **No reverse engineering support**: Built-in tools can't disassemble binaries, inspect PE/ELF headers, find function boundaries, or search cross-references. agent-tool includes static binary analysis (disassembly, xref, function detection), a DAP debugger, and CheatEngine-style memory tools -- giving your agent full reverse engineering capabilities.
- **Network censorship**: In some countries, government-level web filtering breaks plain `curl`/`wget` requests. agent-tool uses ECH (Encrypted Client Hello) and DoH (DNS over HTTPS) by default to work around these restrictions.

**agent-tool** solves these by providing drop-in replacement tools that respect your project's conventions.

## Supported Agents

Claude Code, Codex CLI, Cursor, Windsurf, Cline, Gemini CLI, and any MCP-compatible agent.

## Features

| Tool | Description | Status |
|------|-------------|--------|
| **Edit** | String replacement with smart indentation and encoding preservation (supports dry_run) | ✅ |
| **Read** | Encoding-aware file reading with flexible offset (integer, `"N-M"` range, `[N,M]` array). Image files (PNG/JPG/GIF/BMP/WebP/TIFF/ICO) returned as base64 ImageContent | ✅ |
| **Write** | Encoding-aware file creation/overwrite | ✅ |
| **Grep** | Encoding-aware regex content search with output modes (content/files_with_matches/count) and context lines (-B/-A/-C) | ✅ |
| **Glob** | File pattern matching with `**` recursive support | ✅ |
| **ListDir** | Directory listing (flat or tree) | ✅ |
| **Diff** | Compare two files with unified diff output (encoding-aware) | ✅ |
| **Patch** | Apply unified diff patch to a file (supports dry_run) | ✅ |
| **Checksum** | Compute file hash (md5, sha1, sha256) | ✅ |
| **FileInfo** | File metadata (size, encoding, line ending, indentation, line count) | ✅ |
| **Compress** | Create zip / tar.gz archives | ✅ |
| **Decompress** | Extract zip / tar.gz archives (Zip Slip/Bomb protection) | ✅ |
| **Backup** | Timestamped zip backup with exclude patterns. dry_run preview with directory stats, pattern match counts, and largest files | ✅ |
| **ConvertEncoding** | Convert file encoding (EUC-KR ↔ UTF-8, add/remove BOM, etc.) | ✅ |
| **Delete** | Safe single-file deletion (no directories, no symlinks, system path protection, dry_run) | ✅ |
| **Rename** | Atomic file/directory rename or move (dry_run) | ✅ |
| **SysInfo** | System information — OS, CPU, RAM, disk, uptime, CPU usage measurement | ✅ |
| **FindTools** | Discover installed dev tools — compilers, runtimes, build systems (Go, .NET, Node, Python, Java, Rust, C/C++, etc.). Searches PATH, env vars, and known locations (~/bin, snap, scoop, Homebrew, SDKMAN, nvm, fnm, pyenv) | ✅ |
| **ProcList** | List running processes — PID, name, command line, memory. Sensitive args auto-masked. Filter by name or port | ✅ |
| **ProcKill** | Kill, suspend, or resume processes by PID or port. Tree kill, signal selection (kill/term/hup/int/stop/cont), zombie handling (Linux), dry_run | ✅ |
| **ProcExec** | Execute commands as new processes. Foreground/background/suspended start (Windows: CREATE_SUSPENDED, Linux: SIGSTOP). Timeout, env vars | ✅ |
| **EnvVar** | Read environment variables. Sensitive values (passwords, tokens) auto-masked | ✅ |
| **Firewall** | Read firewall rules — iptables/nftables/firewalld (Linux), netsh (Windows). Read-only | ✅ |
| **SSH** | Execute commands on remote servers via SSH. Password & key auth (PEM, OpenSSH, PuTTY PPK), session pooling, host key verification (strict/tofu/none), ProxyJump, IPv6 | ✅ |
| **SFTP** | Transfer files and manage remote filesystems over SSH. Upload, download, ls, stat, mkdir, rm, chmod, rename. Reuses SSH session pool. Max 2 GB per transfer | ✅ |
| **Bash** | Persistent shell sessions with working directory and environment variable retention. Session pooling (max 5, idle timeout 30 min). Unix: bash/sh, Windows: PowerShell/git-bash/cmd (auto-detected, best available). PowerShell sessions include UTF-8 encoding and PATH enhancement | ✅ |
| **WebFetch** | Fetch web content as text/Markdown. ECH (Encrypted Client Hello) + DoH (DNS over HTTPS) by default. HTML→Markdown auto-conversion. SSRF protection. HTTP/SOCKS5 proxy. Chrome User-Agent. **Note:** Returns full page content (default 100K chars) which consumes context window tokens — use `max_length` to limit, or prefer your agent's built-in web tools for simple searches | ✅ |
| **WebSearch** | Web search via Brave Search or Naver API. Requires API key env vars (`BRAVE_SEARCH_API_KEY` or `NAVER_CLIENT_ID`/`NAVER_CLIENT_SECRET`). Auto-selects engine, Brave preferred | ✅ |
| **Download** | Download files from URLs to disk. ECH + DoH by default. SSRF protection. HTTP/SOCKS5 proxy. Atomic write. Max 2 GB | ✅ |
| **HTTPReq** | Execute HTTP requests with any method (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS). API testing with custom headers, body, proxy. SSRF protection | ✅ |
| **JSONQuery** | Query JSON files with dot-notation paths (e.g. `dependencies.react`, `items[*].id`). Extract specific values without loading entire file into context | ✅ |
| **YAMLQuery** | Query YAML files with dot-notation paths (same syntax as JSONQuery) | ✅ |
| **TOMLQuery** | Query TOML files with dot-notation paths (same syntax as JSONQuery). Supports TOML-specific types (datetime, int64) | ✅ |
| **Copy** | Copy files/directories with atomic write and permission preservation. Recursive directory copy. Windows locked-file fallback (renames running exe/DLL aside). dry_run preview | ✅ |
| **Mkdir** | Create directories with optional permission mode (octal, e.g. 0755). Recursive by default (mkdir -p). dry_run preview | ✅ |
| **MultiRead** | Read multiple files in a single call to reduce API round-trips. Encoding-aware, offset/limit support. Max 50 files | ✅ |
| **RegexReplace** | Regex find-and-replace across files/directories. Encoding-preserving, capture groups ($1, $2). dry_run preview | ✅ |
| **TLSCheck** | Check TLS certificate details — subject, issuer, expiry, SANs, TLS version, cipher suite | ✅ |
| **DNSLookup** | DNS record lookup (A/AAAA/MX/CNAME/TXT/NS/SOA). DNS over HTTPS (DoH) by default for privacy | ✅ |
| **MySQL** | Execute SQL queries on MySQL/MariaDB. Table-formatted SELECT results, affected rows for DML. Max 1000 rows | ✅ |
| **Redis** | Execute Redis commands with formatted output by type. TLS support. Dangerous commands (FLUSHALL, SHUTDOWN, etc.) blocked | ✅ |
| **PortCheck** | Check if a TCP port is open on a host. Returns OPEN/CLOSED with response time. Supports hostname, IPv4, IPv6 | ✅ |
| **ExternalIP** | Get your external (public) IP address. Multiple providers with automatic fallback (ipify, ifconfig.me, icanhazip) | ✅ |
| **SLOC** | Count source lines of code per language. 70+ language detection, per-file/language breakdown, blank line stats, max_depth control | ✅ |
| **Debug** | Interactive debugger via DAP (Debug Adapter Protocol). Full DAP coverage: breakpoints (source/function/data/instruction/exception), stepping (forward/backward), variable inspection and modification, expression evaluation, disassembly, memory read/write, stack traces, modules, goto, completions. Tested with dlv (Go), debugpy (Python), codelldb (C/C++/Rust). Works with any DAP-compatible adapter. Stdio and TCP modes. Note: vsdbg (Microsoft) requires VS Code licensing and is not usable standalone — use codelldb or netcoredbg as open-source alternatives | ✅ |
| **Analyze** | Static binary analysis and reverse engineering. x86/x64/ARM/ARM64 disassembly (PE/ELF/Mach-O, auto VA display, symbol annotation, stop_at_ret). PE/ELF/Mach-O parsing (RWX warnings, resources, imports with IAT VA, exports). xref (PE/ELF/Mach-O, x86/x64/ARM64/ARM32, summary stats). function_at (.pdata or heuristic prologue/epilogue scan). call_graph (PE/ELF/Mach-O, x86/x64/ARM64/ARM32). follow_ptr (pointer chain tracing with circular detection). rtti_dump (MSVC RTTI parsing with class name demangling, pSelf validation). vtable_scan (auto-discover vtables with RTTI in .rdata). struct_layout (memory layout annotation). imphash, Rich header, DWARF debug info, string extraction (with VA), hexdump, hex pattern search (with section names), entropy analysis, overlay detection, binary diff. No global file size limit | ✅ |
| **Memtool** | CheatEngine-style process memory tool — search/filter/read/write memory values, live disassembly (x86/x64/ARM/ARM64), undo, struct pattern search, pointer scan, memory diff. Disk-backed snapshots for large scans. Session management with idle timeout. Windows (ReadProcessMemory) and Linux (/proc/pid/mem) | ✅ |
| **IPC** | Inter-process communication between AI agent sessions over TCP. 1:1 message passing with blocking receive. Protocol: [2-byte type][4-byte length][payload]. Operations: send, receive (blocking with timeout), ping. Works across machines. Max 1MB message, 300s timeout | ✅ |
| **Wintool** | Windows GUI automation — find/enumerate windows and child controls, capture screenshots (ImageContent PNG via PrintWindow), read clipboard images, read/set text, click, type, send raw messages, show/hide/minimize/maximize, move/resize, close, focus. screenshot/clipboard return ImageContent by default (save_path option for file output). Enables AI agents to "see" and interact with GUI applications. Windows only | ✅ |
| **SetConfig** | Change runtime settings (encoding, file size limit, symlinks, workspace, etc.) | ✅ |
| **Help** | Built-in usage guide for agents (encoding, indentation, troubleshooting) | ✅ |

## Key Improvements

### Smart Indentation
LLMs typically output spaces, but many projects use tabs. AgentTool auto-converts indentation to match the file's existing style.

- Reads `.editorconfig` for `indent_style` and `indent_size`
- Falls back to content-based detection (first 100 lines)
- Protects legacy files: won't convert if actual content contradicts `.editorconfig`

### Encoding Preservation
Edits preserve the original file encoding instead of forcing UTF-8.

- **Detection priority**: `.editorconfig` charset → chardet auto-detection → fallback encoding
- **Supported**: UTF-8, UTF-8 BOM, EUC-KR, Shift-JIS, ISO-8859-1, UTF-16, and more
- **Line endings**: Preserves `\r\n` / `\n` as-is

## Quick Start

1. Download the binary for your OS from [Releases](https://github.com/knewstimek/agent-tool/releases/latest)
2. Run `agent-tool install` (or `agent-tool install claude` for a specific agent)
3. Restart your IDE / agent
4. Done — all tools are available immediately with no permission popups

Or just ask your AI agent to do it for you:
> "Download agent-tool from https://github.com/knewstimek/agent-tool/releases/latest and run `agent-tool install`"

Any capable AI coding agent (Claude Code, Codex, etc.) can handle the full download → install → restart flow automatically.

### Recommended: Tell your agent to prefer agent-tool

After installing, agents will have access to agent-tool but may still default to built-in tools (Read, Edit, etc.). To ensure agents **prefer** agent-tool's encoding-aware, indentation-smart tools, add one of the instructions below.

Pick **Strict** or **Soft**:

| Mode | When to use | Instruction |
|------|-------------|-------------|
| **Strict** | Projects with non-UTF-8 files or mixed indentation | `ALWAYS use agent-tool MCP tools (mcp__agent-tool__*) instead of built-in file tools. agent-tool preserves file encoding and respects .editorconfig indentation settings.` |
| **Soft** | General projects | `Prefer agent-tool MCP tools (mcp__agent-tool__*) over built-in file tools when available.` |

**Where to put it:**

<details>
<summary><b>Claude Code</b> — CLAUDE.md (per-project) or global instructions</summary>

**Per-project** — add to your project's `CLAUDE.md`:
```
ALWAYS use agent-tool MCP tools (mcp__agent-tool__*) instead of built-in file tools.
```

**Global** (all projects) — add to `~/.claude/CLAUDE.md`:
```
ALWAYS use agent-tool MCP tools (mcp__agent-tool__*) instead of built-in file tools.
```
</details>

<details>
<summary><b>Codex CLI</b> — model_instructions.md (global)</summary>

1. Add to `~/.codex/config.toml` (top-level, **not** inside `[mcp_servers.*]`):
```toml
model_instructions_file = "~/.codex/model_instructions.md"
```

2. Create `~/.codex/model_instructions.md`:
```
ALWAYS use agent-tool MCP tools (mcp__agent-tool__*) instead of built-in file tools.
```

3. Restart Codex.

**Per-project** — add to your project's `AGENTS.md` instead.
</details>

<details>
<summary><b>Cursor / Windsurf / Cline</b> — .cursorrules or AGENTS.md</summary>

Add to your project's `.cursorrules`, `.windsurfrules`, or `AGENTS.md`:
```
ALWAYS use agent-tool MCP tools (mcp__agent-tool__*) instead of built-in file tools.
```
</details>

## Installation

### Auto-install (recommended)

```bash
# Register with all detected agents (full auto-approve — all tools)
agent-tool install

# Safe mode — only auto-approve local file tools (no SSH, HTTP, DB, shell)
agent-tool install --safe-approve

# No auto-approve — manual approval required for every tool call
agent-tool install --no-auto-approve

# Register with a specific agent
agent-tool install claude
agent-tool install claude --safe-approve

# Uninstall (removes agent-tool entry only, preserves other settings)
agent-tool uninstall          # from all agents
agent-tool uninstall claude   # from specific agent
```

**Install permission levels:**

| Level | Flag | Auto-approved tools |
|-------|------|---------------------|
| Full (default) | _(none)_ | All tools (`mcp__agent-tool__*` wildcard) |
| Safe | `--safe-approve` | 29 local-only tools (read, edit, write, grep, glob, etc.) — no SSH, HTTP, DB, bash, process control |
| None | `--no-auto-approve` | No tools — every call requires manual approval |

### Manual setup

**Claude Code / Cursor / Cline** (`settings.json` or `mcp.json`):
```json
{
  "mcpServers": {
    "agent-tool": {
      "command": "/path/to/agent-tool"
    }
  }
}
```

**Codex CLI** (`~/.codex/config.toml`):
```toml
[mcp_servers.agent-tool]
command = "/path/to/agent-tool"
```

### Options

```bash
# Set fallback encoding for projects with non-UTF-8 files
agent-tool --fallback-encoding EUC-KR
```

### Environment Variable

Set `AGENT_TOOL_FALLBACK_ENCODING` to avoid repeating the CLI flag every session:

```bash
# Windows (no admin required)
setx AGENT_TOOL_FALLBACK_ENCODING EUC-KR

# Linux / macOS (add to ~/.bashrc or ~/.zshrc)
export AGENT_TOOL_FALLBACK_ENCODING=EUC-KR
```

Priority: CLI flag > environment variable > default (UTF-8).

### Runtime Configuration

Agents can change settings at runtime via `set_config` without restarting:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `fallback_encoding` | Fallback encoding when auto-detection fails | `UTF-8` |
| `encoding_warnings` | Show encoding detection warnings | `true` |
| `max_file_size_mb` | Max file size for read/edit/grep (MB) | `50` |
| `allow_symlinks` | Allow symlink extraction from tar archives | `false` |
| `workspace` | Default workspace/project root for tools like glob when no explicit path is given | _(cwd)_ |
| `allow_http_private` | Allow webfetch/download/httpreq to access private IPs | `false` |
| `allow_mysql_private` | Allow mysql tool to access private IPs | `true` |
| `allow_redis_private` | Allow redis tool to access private IPs | `true` |
| `allow_ssh_private` | Allow ssh/sftp tools to access private IPs | `true` |
| `enable_doh` | Enable DNS over HTTPS globally (webfetch/download/httpreq/dnslookup) | `true` |
| `enable_ech` | Enable Encrypted Client Hello globally (webfetch/download/httpreq) | `true` |

## Build

```bash
go build -o agent-tool .
```

Cross-compile:
```bash
GOOS=linux GOARCH=amd64 go build -o agent-tool .
GOOS=darwin GOARCH=arm64 go build -o agent-tool .
GOOS=windows GOARCH=amd64 go build -o agent-tool.exe .
```

## Troubleshooting

### Garbled text (encoding issues)

If Korean, Japanese, or other non-ASCII text appears as garbage characters:

**Option 1**: Add `charset` to your `.editorconfig`:
```ini
[*]
charset = euc-kr
```

**Option 2**: Set environment variable (persistent):
```bash
setx AGENT_TOOL_FALLBACK_ENCODING EUC-KR   # Windows
export AGENT_TOOL_FALLBACK_ENCODING=EUC-KR  # Linux
```

**Option 3**: CLI flag (per-session):
```bash
agent-tool --fallback-encoding EUC-KR
```

### Built-in help for agents

agent-tool includes a `agent_tool_help` tool that agents can call for usage guidance. When an agent encounters encoding warnings or garbled text, it can call:

```json
{ "tool": "agent_tool_help", "arguments": { "topic": "encoding" } }
```

Available topics: `overview`, `encoding`, `indentation`, `tools`, `troubleshooting`

## Security

agent-tool provides powerful system access (SSH, MySQL, Redis, file operations, HTTP requests).
When used with AI coding agents, be aware of prompt injection risks:

- **SSRF Protection**: Cloud metadata IPs (169.254.x.x, fe80::/10) are always blocked regardless of settings. Private IP access is configurable per protocol via `set_config` (`allow_http_private`, `allow_mysql_private`, `allow_redis_private`, `allow_ssh_private`)
- **DLP (Data Loss Prevention)**: All outbound HTTP request bodies are scanned for sensitive data patterns (PEM private keys, AWS access keys, GitHub/GitLab tokens, Slack tokens, .env file dumps) and **blocked before transmission**
- **Prompt Injection Warnings**: Every private IP connection shows a security warning visible to both the user and the AI agent, helping detect prompt injection attacks from fetched web content
- **Zip Slip protection**: Archive entries with `../` path traversal are blocked (both zip and tar)
- **Zip Bomb protection**: Single file limit (1GB), total extraction limit (5GB)
- **Symlinks**: Skipped by default. Enable via `set_config allow_symlinks=true` (tar only; zip symlinks always skipped). Even when enabled, symlinks targeting outside the output directory are blocked
- **File size limit**: Configurable max file size (default 50MB) prevents OOM on large files. Adjustable via `set_config max_file_size_mb=N`
- **Encoding safety**: chardet uses 64KB sample (not full file) for memory efficiency

For maximum security, review the AI agent's tool calls before approving, especially for SSH commands, HTTP requests to external URLs, and database queries.

## Tech Stack

- **Language**: Go
- **MCP SDK**: [github.com/modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk)
- **Encoding**: saintfish/chardet + golang.org/x/text
- **Distribution**: Single binary (cross-compiled)

## License

[MIT](LICENSE)
