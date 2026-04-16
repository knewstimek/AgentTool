package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"agent-tool/common"
	"agent-tool/install"
	bashtool "agent-tool/tools/bash"
	"agent-tool/tools/analyze"
	"agent-tool/tools/codegraph"
	"agent-tool/tools/backup"
	"agent-tool/tools/download"
	"agent-tool/tools/checksum"
	"agent-tool/tools/compress"
	copytool "agent-tool/tools/copy"
	"agent-tool/tools/config"
	"agent-tool/tools/convertenc"
	"agent-tool/tools/debug"
	"agent-tool/tools/delete"
	"agent-tool/tools/diff"
	"agent-tool/tools/dnslookup"
	edit "agent-tool/tools/edit"
	"agent-tool/tools/multiedit"
	"agent-tool/tools/envvar"
	"agent-tool/tools/externalip"
	"agent-tool/tools/fileinfo"
	"agent-tool/tools/findtools"
	"agent-tool/tools/firewall"
	"agent-tool/tools/glob"
	"agent-tool/tools/grep"
	"agent-tool/tools/help"
	"agent-tool/tools/httpreq"
	"agent-tool/tools/jsonquery"
	"agent-tool/tools/listdir"
	"agent-tool/tools/mkdir"
	"agent-tool/tools/memtool"
	mysqltool "agent-tool/tools/mysql"
	"agent-tool/tools/multiread"
	"agent-tool/tools/tomlquery"
	"agent-tool/tools/patch"
	"agent-tool/tools/portcheck"
	"agent-tool/tools/regexreplace"
	"agent-tool/tools/procexec"
	"agent-tool/tools/prockill"
	"agent-tool/tools/proclist"
	"agent-tool/tools/read"
	redistool "agent-tool/tools/redis"
	"agent-tool/tools/rename"
	sftptool "agent-tool/tools/sftp"
	"agent-tool/tools/sloc"
	"agent-tool/tools/ssh"
	"agent-tool/tools/sysinfo"
	"agent-tool/tools/tlscheck"
	"agent-tool/tools/webfetch"
	"agent-tool/tools/websearch"
	"agent-tool/tools/yamlquery"
	"agent-tool/tools/ipc"
	"agent-tool/tools/wintool"
	"agent-tool/tools/write"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const Version = "v0.8.5"

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

	// Reject unknown subcommands/flags to avoid hanging on stdin
	if len(args) > 0 && args[0] != "--fallback-encoding" {
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
		fmt.Fprintf(os.Stderr, "usage: agent-tool [install|uninstall|reinstall|version] [--fallback-encoding ENC]\n")
		os.Exit(1)
	}
	// Guard: --fallback-encoding without a value would silently start MCP server
	if len(args) == 1 && args[0] == "--fallback-encoding" {
		fmt.Fprintf(os.Stderr, "error: --fallback-encoding requires a value (e.g. --fallback-encoding EUC-KR)\n")
		os.Exit(1)
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

Tool groups: file | system (bash, procexec, proclist, prockill, sysinfo, envvar, firewall, memtool, wintool (GUI/screenshot/clipboard), ipc (agent messaging/broker)) | network (httpreq, webfetch, websearch, sftp, ssh, download, dnslookup, tlscheck, portcheck, externalip) | data (jsonquery, yamlquery, tomlquery, mysql, redis) | analysis (analyze, debug, codegraph, find_tools) | config (set_config, mkdir, help)`,
		},
	)

	edit.Register(server)
	multiedit.Register(server)
	read.Register(server)
	write.Register(server)
	grep.Register(server)
	glob.Register(server)
	listdir.Register(server)
	compress.RegisterCompress(server)
	compress.RegisterDecompress(server)
	backup.Register(server)
	config.Register(server)
	convertenc.Register(server)
	checksum.Register(server)
	fileinfo.Register(server)
	diff.Register(server)
	patch.Register(server)
	delete.Register(server)
	rename.Register(server)
	copytool.Register(server)
	mkdir.Register(server)
	multiread.Register(server)
	sysinfo.Register(server)
	findtools.Register(server)
	proclist.Register(server)
	prockill.Register(server)
	procexec.Register(server)
	envvar.Register(server)
	firewall.Register(server)
	ssh.Register(server)
	sftptool.Register(server)
	bashtool.Register(server)
	webfetch.Register(server)
	websearch.Register(server)
	download.Register(server)
	httpreq.Register(server)
	jsonquery.Register(server)
	yamlquery.Register(server)
	tomlquery.Register(server)
	portcheck.Register(server)
	regexreplace.Register(server)
	tlscheck.Register(server)
	dnslookup.Register(server)
	mysqltool.Register(server)
	redistool.Register(server)
	externalip.Register(server)
	sloc.Register(server)
	debug.Register(server)
	analyze.Register(server)
	memtool.Register(server)
	wintool.Register(server)
	ipc.Register(server)
	codegraph.Register(server)
	help.Register(server)

	// Monitor parent process -- exit if parent dies to prevent orphan processes.
	// When the parent (IDE/CLI) is killed, stdin pipe may not close properly
	// (especially on Windows), leaving this process alive consuming memory.
	go monitorParent()

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
