package redis

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	goredis "github.com/redis/go-redis/v9"
)

const (
	defaultPort           = 6379
	defaultTimeoutSec     = 30
	maxTimeoutSec         = 120
	defaultMaxValueChars  = 200
	hardMaxValueChars     = 10000
	defaultMaxOutputChars = common.DefaultOutputChars
	hardMaxOutputChars    = common.HardOutputChars
	outputTruncatedSuffix = "\n[Output truncated]"
)

// dangerousCommands are blocked to prevent accidental data loss or server disruption.
// These commands can flush databases, shut down servers, or execute arbitrary scripts.
var dangerousCommands = map[string]bool{
	"FLUSHALL": true, "FLUSHDB": true,
	"SHUTDOWN": true, "DEBUG": true,
	"REPLICAOF": true, "SLAVEOF": true,
	"CONFIG": true, "CLUSTER": true,
	"SCRIPT": true, "EVAL": true, "EVALSHA": true,
	"EVALRO": true, "EVALSHA_RO": true,
	"FUNCTION": true, "RESTORE": true,
	"MODULE": true, "ACL": true, "BGSAVE": true,
	"BGREWRITEAOF": true, "FAILOVER": true,
	"SUBSCRIBE": true, "PSUBSCRIBE": true, "MONITOR": true,
	"WAIT": true, "CLIENT": true, "SWAPDB": true,
	"MIGRATE": true, "OBJECT": true, "LATENCY": true,
	"MEMORY": true, "SLOWLOG": true,
}

type RedisInput struct {
	Host           string      `json:"host" jsonschema:"Redis server hostname or IP address,required"`
	Port           interface{} `json:"port,omitempty" jsonschema:"Redis port number. Default: 6379"`
	Password       string      `json:"password,omitempty" jsonschema:"Password for authentication"`
	DB             interface{} `json:"db,omitempty" jsonschema:"Redis database number. Default: 0"`
	Command        string      `json:"command" jsonschema:"Redis command (e.g. GET, SET, HGETALL),required"`
	Args           []string    `json:"args,omitempty" jsonschema:"Command arguments"`
	TimeoutSec     interface{} `json:"timeout_sec,omitempty" jsonschema:"Command timeout in seconds. Default: 30, Max: 120"`
	TLS            interface{} `json:"tls,omitempty" jsonschema:"Use TLS encryption: true or false. Default: false"`
	MaxValueChars  int         `json:"max_value_chars,omitempty" jsonschema:"Maximum characters displayed per value. Default: 200, Max: 10000"`
	MaxOutputChars int         `json:"max_output_chars,omitempty" jsonschema:"Maximum total returned text characters. Default: 32768, Max: 131072"`
}

type RedisOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input RedisInput) (*mcp.CallToolResult, RedisOutput, error) {
	// Validate required fields
	input.Host = strings.TrimSpace(input.Host)
	if input.Host == "" {
		return errorResult("host is required")
	}
	input.Command = strings.TrimSpace(input.Command)
	if input.Command == "" {
		return errorResult("command is required")
	}

	// Block dangerous commands that could cause data loss or server disruption
	cmdUpper := strings.ToUpper(input.Command)
	if dangerousCommands[cmdUpper] {
		return errorResult(fmt.Sprintf("blocked: %s is a dangerous command", input.Command))
	}

	// Defaults
	port, ok := common.FlexInt(input.Port)
	if !ok {
		return errorResult("port must be an integer")
	}
	db, ok := common.FlexInt(input.DB)
	if !ok {
		return errorResult("db must be an integer")
	}
	timeoutSec, ok := common.FlexInt(input.TimeoutSec)
	if !ok {
		return errorResult("timeout_sec must be an integer")
	}
	if port == 0 {
		port = defaultPort
	}
	if port < 1 || port > 65535 {
		return errorResult(fmt.Sprintf("invalid port: %d (must be 1-65535)", port))
	}
	if timeoutSec <= 0 {
		timeoutSec = defaultTimeoutSec
	}
	if timeoutSec > maxTimeoutSec {
		return errorResult(fmt.Sprintf("timeout_sec exceeds maximum (%d)", maxTimeoutSec))
	}
	if input.MaxValueChars <= 0 {
		input.MaxValueChars = defaultMaxValueChars
	}
	if input.MaxValueChars > hardMaxValueChars {
		return errorResult(fmt.Sprintf("max_value_chars must be at most %d", hardMaxValueChars))
	}
	if input.MaxOutputChars <= 0 {
		input.MaxOutputChars = defaultMaxOutputChars
	}
	if input.MaxOutputChars > hardMaxOutputChars {
		return errorResult(fmt.Sprintf("max_output_chars must be at most %d", hardMaxOutputChars))
	}

	// SSRF policy: cloud metadata always blocked. Private IPs allowed by default
	// (configurable via set_config allow_redis_private). Warning shown on every
	// private IP access to help detect prompt injection attacks.
	// Use resolved IP for connection to prevent DNS rebinding (TOCTOU).
	resolvedIP, ssrfWarning, ssrfErr := common.CheckHostSSRF(ctx, input.Host, common.GetAllowRedisPrivate(), "redis")
	if ssrfErr != nil {
		return errorResult(ssrfErr.Error())
	}
	connectAddr := input.Host
	if resolvedIP != "" {
		connectAddr = resolvedIP
	}

	timeout := time.Duration(timeoutSec) * time.Second

	opts := newRedisOptions(input, connectAddr, port, db, timeout)

	client := goredis.NewClient(opts)
	defer client.Close()

	opCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build command args: command + args as []interface{}
	cmdArgs := make([]interface{}, 0, 1+len(input.Args))
	cmdArgs = append(cmdArgs, input.Command)
	for _, arg := range input.Args {
		cmdArgs = append(cmdArgs, arg)
	}

	cmd := client.Do(opCtx, cmdArgs...)
	if cmd.Err() != nil {
		return errorResult(fmt.Sprintf("Redis error: %s", sanitizeError(cmd.Err(), input.Password)))
	}

	result := formatResult(cmd, input.MaxValueChars, input.MaxOutputChars)

	// Prepend SSRF warning if connecting to a private IP
	if ssrfWarning != "" {
		result = ssrfWarning + "\n\n" + result
		result, _ = common.TruncateRunes(result, input.MaxOutputChars, outputTruncatedSuffix)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, RedisOutput{Result: result}, nil
}

func newRedisOptions(input RedisInput, connectAddr string, port, db int, timeout time.Duration) *goredis.Options {
	opts := &goredis.Options{
		Addr:         fmt.Sprintf("%s:%d", connectAddr, port),
		Password:     input.Password,
		DB:           db,
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	}

	if common.FlexBool(input.TLS) {
		opts.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: input.Host,
		}
	}
	return opts
}

// formatResult converts the Redis command result into a human-readable string.
func formatResult(cmd *goredis.Cmd, maxValueChars, maxOutputChars int) string {
	val := cmd.Val()

	var result string
	switch v := val.(type) {
	case nil:
		result = "(nil)\n"
	case string:
		result = fmt.Sprintf("%q\n", boundedRedisValue(v, maxValueChars))
	case int64:
		result = fmt.Sprintf("(integer) %d\n", v)
	case []interface{}:
		return formatSlice(v, maxValueChars, maxOutputChars)
	default:
		result = boundedRedisValue(fmt.Sprintf("%v", v), maxValueChars) + "\n"
	}

	result, _ = common.TruncateRunes(result, maxOutputChars, outputTruncatedSuffix)
	return result
}

// formatSlice formats a Redis array response with indexed elements.
func formatSlice(items []interface{}, maxValueChars, maxOutputChars int) string {
	if len(items) == 0 {
		return "(empty array)\n"
	}

	var sb strings.Builder
	usedChars := 0
	truncated := false
	for i, item := range items {
		var line string
		switch v := item.(type) {
		case nil:
			line = fmt.Sprintf("%d) (nil)\n", i+1)
		case string:
			line = fmt.Sprintf("%d) %q\n", i+1, boundedRedisValue(v, maxValueChars))
		case int64:
			line = fmt.Sprintf("%d) (integer) %d\n", i+1, v)
		case []interface{}:
			line = fmt.Sprintf("%d) (array with %d elements)\n", i+1, len(v))
		default:
			line = fmt.Sprintf("%d) %s\n", i+1, boundedRedisValue(fmt.Sprintf("%v", v), maxValueChars))
		}
		if !common.AppendWithinRuneBudget(&sb, &usedChars, line, maxOutputChars) {
			truncated = true
			break
		}
	}

	result := sb.String()
	if truncated {
		result += outputTruncatedSuffix
	}
	result, _ = common.TruncateRunes(result, maxOutputChars, outputTruncatedSuffix)
	return result
}

func boundedRedisValue(value string, maxValueChars int) string {
	value, _ = common.TruncateRunes(value, maxValueChars, "…")
	return value
}

// sanitizeError removes password from error messages.
func sanitizeError(err error, password string) string {
	msg := err.Error()
	if password != "" {
		msg = strings.ReplaceAll(msg, password, "***")
	}
	return msg
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "redis",
		Description: `Execute Redis commands on a Redis server.
Supports all Redis commands (GET, SET, HGETALL, LPUSH, etc.).
Results are formatted by type: strings, integers, arrays, and nil values.
Connection is closed after each call (no session pooling).
Supports verified TLS encryption for secure connections.
Defaults: 200 characters per value and 32768 total output characters.
Use max_value_chars/max_output_chars to tune bounded output.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, RedisOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, RedisOutput{}, nil
}
