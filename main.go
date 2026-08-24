package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"agent-tool/common"
	"agent-tool/install"
	"agent-tool/tools/analyze"
	"agent-tool/tools/backup"
	bashtool "agent-tool/tools/bash"
	"agent-tool/tools/checksum"
	"agent-tool/tools/codegraph"
	"agent-tool/tools/compress"
	"agent-tool/tools/config"
	"agent-tool/tools/convertenc"
	copytool "agent-tool/tools/copy"
	"agent-tool/tools/debug"
	"agent-tool/tools/delete"
	"agent-tool/tools/diff"
	"agent-tool/tools/dnslookup"
	"agent-tool/tools/download"
	edit "agent-tool/tools/edit"
	"agent-tool/tools/envvar"
	"agent-tool/tools/externalip"
	"agent-tool/tools/fileinfo"
	"agent-tool/tools/findtools"
	"agent-tool/tools/firewall"
	"agent-tool/tools/glob"
	"agent-tool/tools/grep"
	"agent-tool/tools/help"
	"agent-tool/tools/httpreq"
	"agent-tool/tools/ipc"
	"agent-tool/tools/jsonquery"
	"agent-tool/tools/listdir"
	"agent-tool/tools/memtool"
	"agent-tool/tools/mkdir"
	"agent-tool/tools/multiedit"
	"agent-tool/tools/multiread"
	mysqltool "agent-tool/tools/mysql"
	"agent-tool/tools/patch"
	"agent-tool/tools/portcheck"
	"agent-tool/tools/procexec"
	"agent-tool/tools/prockill"
	"agent-tool/tools/proclist"
	"agent-tool/tools/read"
	redistool "agent-tool/tools/redis"
	"agent-tool/tools/regexreplace"
	"agent-tool/tools/rename"
	sftptool "agent-tool/tools/sftp"
	"agent-tool/tools/sloc"
	"agent-tool/tools/ssh"
	"agent-tool/tools/sysinfo"
	"agent-tool/tools/tlscheck"
	"agent-tool/tools/tomlquery"
	"agent-tool/tools/toolbox"
	"agent-tool/tools/webfetch"
	"agent-tool/tools/websearch"
	"agent-tool/tools/wintool"
	"agent-tool/tools/write"
	"agent-tool/tools/yamlquery"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const Version = "v0.9.4"

func main() {
	args := os.Args[1:]

	// version flag — print version and exit immediately
	if len(args) > 0 && (args[0] == "version" || args[0] == "--version" || args[0] == "-v") {
		fmt.Println("agent-tool " + Version)
		return
	}

	// install / uninstall / reinstall subcommands
	if len(args) > 0 && (args[0] == "install" || args[0] == "uninstall" || args[0] == "reinstall") {
		target := ""
		approveLevel := install.ApproveFull // default: mcp__agent-tool__*
		remaining := args[1:]
		for _, a := range remaining {
			switch a {
			case "--no-auto-approve":
				approveLevel = install.ApproveNone
			case "--safe-approve":
				approveLevel = install.ApproveSafe
			default:
				if target == "" {
					target = a
				}
			}
		}
		var err error
		switch args[0] {
		case "install":
			err = install.Run(target, approveLevel)
		case "uninstall":
			err = install.Uninstall(target)
		case "reinstall":
			// ignore uninstall errors (may not be installed yet)
			install.Uninstall(target)
			err = install.Run(target, approveLevel)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	profile := strings.ToLower(strings.TrimSpace(os.Getenv("AGENT_TOOL_PROFILE")))
	if profile == "" {
		profile = "core"
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--fallback-encoding":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --fallback-encoding requires a value (e.g. EUC-KR)")
				os.Exit(1)
			}
			i++
		case "--profile":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --profile requires core, coding, remote, analysis, or full")
				os.Exit(1)
			}
			profile = strings.ToLower(strings.TrimSpace(args[i+1]))
			i++
		default:
			fmt.Fprintf(os.Stderr, "unknown command or flag: %s\n", args[i])
			fmt.Fprintln(os.Stderr, "usage: agent-tool [--profile PROFILE] [--fallback-encoding ENC]")
			os.Exit(1)
		}
	}

	// fallback-encoding configuration (priority: CLI > env var > default)
	// 1. Read from environment variable
	if envEnc := os.Getenv("AGENT_TOOL_FALLBACK_ENCODING"); envEnc != "" {
		if normalized := config.NormalizeAndValidate(envEnc); normalized != "" {
			common.SetFallbackEncoding(normalized)
		} else {
			common.SetFallbackEncoding(strings.ToUpper(strings.TrimSpace(envEnc)))
		}
	}
	// 2. CLI option (takes priority over env var)
	for i, arg := range args {
		if arg == "--fallback-encoding" && i+1 < len(args) {
			enc := args[i+1]
			normalized := config.NormalizeAndValidate(enc)
			if normalized == "" {
				fmt.Fprintf(os.Stderr, "warning: unknown encoding %q, using as-is. Supported: UTF-8, EUC-KR, Shift_JIS, ISO-8859-1, etc.\n", enc)
				common.SetFallbackEncoding(strings.ToUpper(strings.TrimSpace(enc)))
			} else {
				common.SetFallbackEncoding(normalized)
			}
		}
	}

	// Start MCP server
	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "agent-tool",
			Version: Version,
		},
		&mcp.ServerOptions{
			Instructions: `agent-tool: encoding-aware file/system/analysis tools for AI coding agents.

File tools (read, edit, multiedit, write, grep, glob, listdir, multiread, backup, compress, copy, rename, delete, diff, patch, checksum, file_info, convert_encoding, regexreplace, sloc) preserve original file encoding (UTF-8, EUC-KR, Shift-JIS, etc.) and respect .editorconfig indentation settings -- prefer these over built-in file tools.

Use multiread to read multiple files in a single call. Use help with a topic for detailed usage and parameter docs.

The compact core profile is loaded by default. Use toolbox to enable only the file, coding, system, remote, data, analysis, or Windows group needed for the task. Large text results are bounded and report explicit continuation metadata; relative local paths use MCP roots when available.

Toolbox groups: core (essential edit/read/search) | file (file management/config/query helpers) | coding (shell/process/archive/source helpers) | system (OS/process/IPC tools) | remote (SSH/SFTP/HTTP/network tools) | data (JSON/YAML/TOML/MySQL/Redis) | analysis (binary/debug/codegraph/memory tools) | windows (GUI/screenshot/clipboard tools).`,
		},
	)

	specs := []toolbox.Spec{
		{Name: "edit", Group: "core", Register: func() { edit.Register(server) }},
		{Name: "multiedit", Group: "core", Register: func() { multiedit.Register(server) }},
		{Name: "read", Group: "core", Register: func() { read.Register(server) }},
		{Name: "write", Group: "core", Register: func() { write.Register(server) }},
		{Name: "grep", Group: "core", Register: func() { grep.Register(server) }},
		{Name: "glob", Group: "core", Register: func() { glob.Register(server) }},
		{Name: "listdir", Group: "core", Register: func() { listdir.Register(server) }},
		{Name: "set_config", Group: "file", Register: func() { config.Register(server) }},
		{Name: "checksum", Group: "file", Register: func() { checksum.Register(server) }},
		{Name: "file_info", Group: "file", Register: func() { fileinfo.Register(server) }},
		{Name: "diff", Group: "file", Register: func() { diff.Register(server) }},
		{Name: "patch", Group: "core", Register: func() { patch.Register(server) }},
		{Name: "delete", Group: "file", Register: func() { delete.Register(server) }},
		{Name: "rename", Group: "file", Register: func() { rename.Register(server) }},
		{Name: "copy", Group: "file", Register: func() { copytool.Register(server) }},
		{Name: "mkdir", Group: "file", Register: func() { mkdir.Register(server) }},
		{Name: "multiread", Group: "core", Register: func() { multiread.Register(server) }},
		{Name: "agent_tool_help", Group: "core", Register: func() { help.Register(server) }},

		{Name: "compress", Group: "coding", Register: func() { compress.RegisterCompress(server) }},
		{Name: "decompress", Group: "coding", Register: func() { compress.RegisterDecompress(server) }},
		{Name: "backup", Group: "coding", Register: func() { backup.Register(server) }},
		{Name: "convert_encoding", Group: "coding", Register: func() { convertenc.Register(server) }},
		{Name: "bash", Group: "coding", Register: func() { bashtool.Register(server) }},
		{Name: "procexec", Group: "coding", Register: func() { procexec.Register(server) }},
		{Name: "find_tools", Group: "coding", Register: func() { findtools.Register(server) }},
		{Name: "regexreplace", Group: "coding", Register: func() { regexreplace.Register(server) }},
		{Name: "sloc", Group: "coding", Register: func() { sloc.Register(server) }},

		{Name: "sysinfo", Group: "system", Register: func() { sysinfo.Register(server) }},
		{Name: "proclist", Group: "system", Register: func() { proclist.Register(server) }},
		{Name: "prockill", Group: "system", Register: func() { prockill.Register(server) }},
		{Name: "envvar", Group: "system", Register: func() { envvar.Register(server) }},
		{Name: "firewall", Group: "system", Register: func() { firewall.Register(server) }},
		{Name: "ipc", Group: "system", Register: func() { ipc.Register(server) }},

		{Name: "ssh", Group: "remote", Register: func() { ssh.Register(server) }},
		{Name: "sftp", Group: "remote", Register: func() { sftptool.Register(server) }},
		{Name: "webfetch", Group: "remote", Register: func() { webfetch.Register(server) }},
		{Name: "websearch", Group: "remote", Register: func() { websearch.Register(server) }},
		{Name: "download", Group: "remote", Register: func() { download.Register(server) }},
		{Name: "httpreq", Group: "remote", Register: func() { httpreq.Register(server) }},
		{Name: "portcheck", Group: "remote", Register: func() { portcheck.Register(server) }},
		{Name: "tlscheck", Group: "remote", Register: func() { tlscheck.Register(server) }},
		{Name: "dnslookup", Group: "remote", Register: func() { dnslookup.Register(server) }},
		{Name: "externalip", Group: "remote", Register: func() { externalip.Register(server) }},

		{Name: "jsonquery", Group: "data", Register: func() { jsonquery.Register(server) }},
		{Name: "yamlquery", Group: "data", Register: func() { yamlquery.Register(server) }},
		{Name: "tomlquery", Group: "data", Register: func() { tomlquery.Register(server) }},
		{Name: "mysql", Group: "data", Register: func() { mysqltool.Register(server) }},
		{Name: "redis", Group: "data", Register: func() { redistool.Register(server) }},

		{Name: "debug", Group: "analysis", Register: func() { debug.Register(server) }},
		{Name: "analyze", Group: "analysis", Register: func() { analyze.Register(server) }},
		{Name: "codegraph", Group: "analysis", Register: func() { codegraph.Register(server) }},
		{Name: "memtool", Group: "analysis", Register: func() { memtool.Register(server) }},
		{Name: "wintool", Group: "windows", Register: func() { wintool.Register(server) }},
	}
	toolManager := toolbox.NewManager(server, specs)
	if err := toolManager.EnableProfile(profile); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	toolManager.RegisterTool()

	// Monitor parent process -- exit if parent dies to prevent orphan processes.
	// When the parent (IDE/CLI) is killed, stdin pipe may not close properly
	// (especially on Windows), leaving this process alive consuming memory.
	go monitorParent()

	// Neither watchdog fires when the client is alive but finished with us: a
	// "cmd /c agent-tool" wrapper waits for us while we wait for it, and the
	// client above them holds the pipe open, so no EOF and no parent death ever
	// arrive. Exiting on that guess would kill a session that merely paused, so
	// the server gives its memory back instead.
	common.StartIdleMemoryRelease(common.IdleReleaseAfter)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
