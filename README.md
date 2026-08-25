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
- **Too many separate tools**: Making the agent find, install, and configure Redis CLI, MySQL client, SSH client, etc. is tedious and error-prone. agent-tool bundles 54 tools into one binary and exposes them on demand through compact profiles.
- **No reverse engineering support**: Built-in tools can't disassemble binaries, inspect PE/ELF headers, find function boundaries, or search cross-references. agent-tool includes static binary analysis (disassembly, xref, function detection), a DAP debugger, and CheatEngine-style memory tools -- giving your agent full reverse engineering capabilities.
- **Network censorship**: In some countries, government-level web filtering breaks plain `curl`/`wget` requests. agent-tool uses ECH (Encrypted Client Hello) and DoH (DNS over HTTPS) by default to work around these restrictions.

**agent-tool** solves these with agent-oriented tools that preserve project conventions while keeping model context bounded.

## Supported Agents

Claude Code, Codex CLI, Cursor, Windsurf, Cline, Gemini CLI, and any MCP-compatible agent.

## LLM-efficient by default

The default `core` profile exposes only 11 schemas (including `toolbox`) instead of
all 54. In a protocol-level measurement this reduced the serialized tool list from
about 84 KB (`full`) to 18 KB. Use
`toolbox(operation="describe", tool="ssh", compact=true, tool_operation="execute")`
to load only one operation's fields and required list, then invoke it through
`toolbox(operation="call", tool="ssh", arguments={...})`. The gateway does not
depend on dynamic tool-list refresh, so it works with fixed-binding clients such as
Codex. Describe returns a tool/version-bound `schema_handle`; sending it on a later
describe returns a short unchanged acknowledgement when the schema is still current.
You can also start with `--profile coding|remote|analysis|full`.

Potentially large text responses default to 32K characters with a 128K hard ceiling.
Truncation is always visible and pageable tools return `next_offset` or `next_cursor`.
Local relative paths resolve against an explicit workspace, then the MCP client root.

## Features

| Tool | Description | Status |
|------|-------------|--------|
| **Edit** | String replacement with smart indentation and encoding preservation (supports dry_run) | ✅ |
| **Read** | Encoding-aware, line-numbered reading. Defaults to 400 lines/32K chars, reports truncation and exact `next_offset`, safely handles very long lines, optional SHA-256. Flexible offset and MCP ImageContent support | ✅ |
| **Write** | Encoding-aware file creation/overwrite | ✅ |
| **Grep** | Encoding-aware regex search with 32K output budget, compact file-grouped output, relative paths, `.gitignore`/generated-directory filtering, binary detection, output modes/context, and deterministic `next_cursor` paging without repeated matches | ✅ |
| **Glob** | Sorted, bounded file matching with `**`, relative paths, generated-directory filtering, explicit `has_more`, and deterministic cursor paging | ✅ |
| **ListDir** | Bounded/pageable directory listing. max_entries + continuation cursor, directory/file filters, entry-name glob filters, counts-only mode, flat/tree output | ✅ |
| **Diff** | Compare two files with unified diff output (encoding-aware). Files differing only in line endings or a trailing newline say so instead of returning an empty diff | ✅ |
| **Patch** | Apply unified diff patch to a file (supports dry_run). Each line keeps its own ending, so a mixed CRLF/LF file is not rewritten | ✅ |
| **Checksum** | Compute file hash (md5, sha1, sha256) | ✅ |
| **FileInfo** | File metadata (size, encoding, mixed line-ending counts, indentation, line count) | ✅ |
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
| **ProcExec** | Execute commands as new processes. Foreground/background/suspended start, timeout/env vars, and safe repeated-diagnostic compaction with expiring raw-output retrieval | ✅ |
| **EnvVar** | Read environment variables. Sensitive values (passwords, tokens) auto-masked | ✅ |
| **Firewall** | Read firewall rules — iptables/nftables/firewalld (Linux), netsh (Windows). Read-only | ✅ |
| **SSH** | SSH execution with 32K head+tail capture, original byte counts, proper non-zero-exit errors, and background jobs (`start/status/tail/cancel`). Auth-aware pooling, host-key verification, ProxyJump, IPv6 | ✅ |
| **SFTP** | Transfer files and manage remote filesystems over SSH. Upload, download, ls, stat, mkdir, rm, chmod, rename. Reuses SSH session pool. Max 2 GB per transfer | ✅ |
| **Bash** | Persistent shell sessions with working directory/environment retention, safe repeated-diagnostic compaction, and expiring raw-output retrieval. Session pooling (max 5, idle timeout 30 min). Unix: bash/sh, Windows: PowerShell/git-bash/cmd | ✅ |
| **WebFetch** | Fetch web content as text/Markdown with a 32K default/128K max. ECH + DoH, HTML→Markdown conversion, SSRF protection, proxy support, Chrome User-Agent | ✅ |
| **WebSearch** | Web search via Brave Search or Naver API. Requires API key env vars (`BRAVE_SEARCH_API_KEY` or `NAVER_CLIENT_ID`/`NAVER_CLIENT_SECRET`). Auto-selects engine, Brave preferred | ✅ |
| **Download** | Download files from URLs to disk. ECH + DoH by default. SSRF protection. HTTP/SOCKS5 proxy. Atomic write. Max 2 GB | ✅ |
| **HTTPReq** | Execute HTTP requests with any method (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS). API testing with custom headers, body, proxy. SSRF protection | ✅ |
| **JSONQuery** | Query JSON files with dot-notation paths (e.g. `dependencies.react`, `items[*].id`). Extract specific values without loading entire file into context | ✅ |
| **YAMLQuery** | Query YAML files with dot-notation paths (same syntax as JSONQuery) | ✅ |
| **TOMLQuery** | Query TOML files with dot-notation paths (same syntax as JSONQuery). Supports TOML-specific types (datetime, int64) | ✅ |
| **Copy** | Copy files/directories with atomic write and permission preservation. Recursive directory copy. Windows locked-file fallback (renames running exe/DLL aside). dry_run preview | ✅ |
| **Mkdir** | Create directories with optional permission mode (octal, e.g. 0755). Recursive by default (mkdir -p). dry_run preview | ✅ |
| **MultiRead** | Read up to 50 files with a call-wide 32K budget, 200-line per-file default, long-line safety, and per-file/overall continuation metadata. Hashes are opt-in | ✅ |
| **RegexReplace** | Regex find-and-replace across files/directories. Encoding and line-ending preserving, capture groups ($1, $2). Skips binary files. dry_run preview | ✅ |
| **TLSCheck** | Check TLS certificate details — subject, issuer, expiry, SANs, TLS version, cipher suite | ✅ |
| **DNSLookup** | DNS record lookup (A/AAAA/MX/CNAME/TXT/NS/SOA). DNS over HTTPS (DoH) by default for privacy | ✅ |
| **MySQL** | Execute SQL queries on MySQL/MariaDB. Table-formatted SELECT results with configurable row/column/cell/total-output limits; affected rows for DML. Use SQL LIMIT/OFFSET for paging | ✅ |
| **Redis** | Execute Redis commands with formatted output by type. TLS support. Dangerous commands (FLUSHALL, SHUTDOWN, etc.) blocked | ✅ |
| **PortCheck** | Check if a TCP port is open on a host. Returns OPEN/CLOSED with response time. Supports hostname, IPv4, IPv6 | ✅ |
| **ExternalIP** | Get your external (public) IP address. Multiple providers with automatic fallback (ipify, ifconfig.me, icanhazip) | ✅ |
| **SLOC** | Count source lines of code per language. 70+ language detection, per-file/language breakdown, blank line stats, max_depth control | ✅ |
| **Debug** | Interactive debugger via DAP (Debug Adapter Protocol). Full DAP coverage with bounded values/output and paging for variables, completions, modules, and loaded sources. Tested with dlv (Go), debugpy (Python), codelldb (C/C++/Rust). Works with any DAP-compatible adapter. Stdio and TCP modes. Note: vsdbg (Microsoft) requires VS Code licensing and is not usable standalone — use codelldb or netcoredbg as open-source alternatives | ✅ |
| **Analyze** | Static binary analysis and reverse engineering. x86/x64/ARM/ARM64 disassembly; PE/ELF/Mach-O parsing with bounded, pageable PE import output; xref, function discovery/call graphs, pointer/RTTI/vtable/struct analysis, imphash, Rich header, DWARF, strings, hexdump, pattern search, entropy, overlay detection, and binary diff. No global file size limit | ✅ |
| **Memtool** | CheatEngine-style process memory tool — search/filter/read/write memory values, read_chain (resolve base+offset pointer chains, batched in one call), live disassembly (x86/x64/ARM/ARM64), undo, struct pattern search, pointer scan, memory diff. Disk-backed snapshots for large scans. Session management with idle timeout. Windows (ReadProcessMemory) and Linux (/proc/pid/mem). Windows auto-enables SeDebugPrivilege when elevated; opt-in `force_dacl` bypasses a same-user process's self-hardened DACL (original restored after) | ✅ |
| **IPC** | Inter-process communication between AI agent sessions over TCP. 1:1 message passing with blocking receive. Protocol: [2-byte type][4-byte length][payload]. Operations: send, receive (blocking with timeout), ping. Works across machines. Max 1MB message, 300s timeout | ✅ |
| **Wintool** | Windows GUI automation — find/enumerate windows and child controls, capture screenshots (ImageContent PNG via PrintWindow), read clipboard images, read/set text, click, type, send raw messages, show/hide/minimize/maximize, move/resize, close, focus. screenshot/clipboard return ImageContent by default (save_path option for file output). Enables AI agents to "see" and interact with GUI applications. Windows only | ✅ |
| **CodeGraph** | Fully embedded semantic code graph: Go standard-library AST plus lazy compressed tree-sitter WASM for C/C++, Python, C#, Rust, and Java. Adds declaration/definition identity, return-chain and generic/alias propagation, transitive includes, calibrated overload evidence, virtual/interface dispatch, macro/callback edges, build-condition provenance, and multi-root workspaces. No compiler, language server, external binary, LLM call, or token cost | ✅ |
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

- **Detection priority**: BOM → `.editorconfig` charset → BOM-less UTF-16 → valid UTF-8 → chardet auto-detection → fallback encoding
- **Supported**: UTF-8, UTF-8 BOM, EUC-KR, Shift-JIS, ISO-8859-1, UTF-16 (LE/BE, with or without BOM), and more
- **No false warnings on ASCII**: valid UTF-8 is verified directly, so plain ASCII files never raise a low-confidence warning
- **Line endings**: Detects LF, CRLF, CR, and mixed files. `edit` matches a multi-line `old_string` whether the file uses CRLF or LF, including files that mix both, and text inserted by `edit`/`regexreplace` follows the newline style of the region it lands in, so the rest of the file is left byte-identical

### Token-safe directory listings
`listdir` defaults to 500 entries per page and returns `next_cursor` when more
entries are available. Narrow results with `directories_only`, `files_only`,
`name_pattern` (for example `A*`), or multiple OR patterns in `include`.
Use `counts_only=true` when only matching file/directory counts are needed.

### Idle memory release
After 30 minutes with no tool call, the server returns its heap to the OS. A
stdio MCP server cannot tell an abandoned client from a quiet one -- the process
that spawned it may be alive, finished with it, and still holding the pipe open,
so no EOF ever arrives -- and exiting on that guess would break a session that
merely paused. Releasing the memory is the safe half of that trade: an instance
that once read a 50MB file settles back to its ~20MB baseline instead of holding
200MB for the rest of the machine's uptime. Open shell and ssh sessions survive,
and nothing the client can observe changes.

## Quick Start

1. Download the binary for your OS from [Releases](https://github.com/knewstimek/agent-tool/releases/latest)
2. Run `agent-tool install` (or `agent-tool install claude` for a specific agent)
3. Restart your IDE / agent
4. Done — the compact core tools are available immediately; `toolbox` describes and calls every other tool on demand

Or just ask your AI agent to do it for you:
> "Download agent-tool from https://github.com/knewstimek/agent-tool/releases/latest and run `agent-tool install`"

Any capable AI coding agent (Claude Code, Codex, etc.) can handle the full download → install → restart flow automatically.

### Recommended: Tell your agent to prefer agent-tool

After installing, agents will have access to agent-tool but may still default to built-in tools (Read, Edit, etc.). To ensure agents **prefer** agent-tool's encoding-aware, indentation-smart tools, add one of the instructions below.

**Code navigation tip**: For large projects, add this to your CLAUDE.md / AGENTS.md to enable AST-based code navigation:

```
At the start of a session, run codegraph(op="index", path="<project_root>") to build a code index.
For several repositories sharing one graph, use codegraph(op="index", path="<db_root>", roots=["<source_root_1>", "<source_root_2>"]). Source-root provenance prevents unrelated projects with the same symbol names from contaminating candidates while explicit/transitive includes can still cross roots.
Then use codegraph for structural queries (find, callers, callees, methods, inherits) instead of grep.
```

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

**Hard enforcement** — deny built-in file tools at the permission level via `~/.claude/settings.json`:
```json
{
  "permissions": {
    "deny": ["Read", "Edit", "MultiEdit", "Write", "Glob", "Grep"]
  }
}
```
This makes Claude Code's built-in file tools unavailable, so the agent is forced to use agent-tool. Recommended when you want strict enforcement without relying on prompt instructions.
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

Approval level is independent of schema profile: installation may approve the full
namespace while the server still starts with the token-efficient `core` profile.
`toolbox` is intentionally not auto-approved by `--safe-approve`, because its
`operation=call` gateway can invoke network, shell, database, and process-control
tools. Safe-mode users should review each toolbox approval and avoid granting it a
permanent allow rule unless they intend to trust the full AgentTool namespace.

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
# Select the initial schema profile (default: core)
agent-tool --profile coding

# Set fallback encoding for projects with non-UTF-8 files
agent-tool --fallback-encoding EUC-KR
```

Profiles are additive presets: `core` (11 schemas), `coding` (core plus broader
file/build/shell tools), `remote`, `analysis`, and `full`. At runtime, prefer the
client-independent `toolbox` gateway: `operation=describe` returns one tool's schema
(`compact=true` plus `tool_operation` limits it to one operation), and
`operation=call` invokes it through the stable toolbox binding. Re-send a returned
`schema_handle` to avoid receiving an unchanged schema again. When command
diagnostics are compacted, `operation=output` retrieves the bounded raw output by
its reported ID for 30 minutes and reports `next_offset` when paging is needed. `enable`,
`disable`, and `profile` remain available for clients that honor
`tools/list_changed`; fixed-binding clients can always keep using the gateway.

### Environment Variable

Set `AGENT_TOOL_FALLBACK_ENCODING` and/or `AGENT_TOOL_PROFILE` to avoid repeating CLI flags:

```bash
# Windows (no admin required)
setx AGENT_TOOL_FALLBACK_ENCODING EUC-KR
setx AGENT_TOOL_PROFILE coding

# Linux / macOS (add to ~/.bashrc or ~/.zshrc)
export AGENT_TOOL_FALLBACK_ENCODING=EUC-KR
export AGENT_TOOL_PROFILE=coding
```

Priority: CLI flag > environment variable > default (UTF-8).

### Local SSH/SFTP connection profiles

SSH and SFTP accept either `connection_profile` or a session-local `connection_id`,
so host, user, key, and jump-host fields do not need to be repeated. Profiles are
read from the OS user config directory at `agent-tool/connections.json`; override the
location with `AGENT_TOOL_CONNECTION_PROFILE_FILE`. Keep this file local and explicitly
ignored if it is placed inside a workspace.

```json
{
  "connections": {
    "dev": {
      "host": "192.0.2.10",
      "user": "builder",
      "key_file": "/local/path/to/id_ed25519",
      "host_key_check": "strict",
      "trusted": true
    }
  }
}
```

An initial call returns an opaque `connection_id` that remains reusable by both tools
for 30 minutes. `trusted:true` affects only display: an allowed private-address warning
is shown once per pooled connection instead of on every call; SSRF blocking and cloud
metadata protection are unchanged. SSH also supports `quiet`, `echo_command`, and
`result_only`; the last returns compact JSON centered on `stdout`, `stderr`, and
`exit_code`. SFTP supports `quiet`, `result_only`, and `upload_many` (up to 100 files).

### Runtime Configuration

Agents can change settings at runtime via `set_config` without restarting:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `fallback_encoding` | Fallback encoding when auto-detection fails | `UTF-8` |
| `encoding_warnings` | Show encoding detection warnings | `true` |
| `max_file_size_mb` | Max file size for read/edit/grep (MB) | `100` |
| `allow_symlinks` | Allow symlink extraction from tar archives | `false` |
| `workspace` | Explicit local workspace root. Otherwise the first MCP client root is used, then cwd | _(MCP root/cwd)_ |
| `allow_http_private` | Allow webfetch/download/httpreq to access private IPs | `false` |
| `allow_mysql_private` | Allow mysql tool to access private IPs | `true` |
| `allow_redis_private` | Allow redis tool to access private IPs | `true` |
| `allow_ssh_private` | Allow ssh/sftp tools to access private IPs | `true` |
| `enable_doh` | Enable DNS over HTTPS globally (webfetch/download/httpreq/dnslookup) | `true` |
| `enable_ech` | Enable Encrypted Client Hello globally (webfetch/download/httpreq) | `true` |

## Build

```bash
go build -trimpath -ldflags="-s -w" -o agent-tool .
```

Cross-compile:
```bash
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o agent-tool .
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o agent-tool .
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o agent-tool.exe .
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
- **File size limit**: Configurable max file size (default 100MB) prevents OOM on large files. Adjustable via `set_config max_file_size_mb=N`
- **Encoding safety**: chardet uses 64KB sample (not full file) for memory efficiency

For maximum security, review the AI agent's tool calls before approving, especially for SSH commands, HTTP requests to external URLs, and database queries.

## Tech Stack

- **Language**: Go
- **MCP SDK**: [github.com/modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk)
- **Encoding**: saintfish/chardet + golang.org/x/text
- **Distribution**: Single binary (cross-compiled)

## License

[MIT](LICENSE)
