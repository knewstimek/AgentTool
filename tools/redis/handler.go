package redis

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"agent-tool/common"

	goredis "github.com/redis/go-redis/v9"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultPort       = 6379
	defaultTimeoutSec = 30
	maxTimeoutSec     = 120
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
	Host       string   `json:"host" jsonschema:"Redis server hostname or IP address,required"`
	Port       int      `json:"port,omitempty" jsonschema:"Redis port number. Default: 6379"`
	Password   string   `json:"password,omitempty" jsonschema:"Password for authentication"`
	DB         int      `json:"db,omitempty" jsonschema:"Redis database number. Default: 0"`
	Command    string   `json:"command" jsonschema:"Redis command (e.g. GET, SET, HGETALL),required"`
	Args       []string `json:"args,omitempty" jsonschema:"Command arguments"`
	TimeoutSec int      `json:"timeout_sec,omitempty" jsonschema:"Command timeout in seconds. Default: 30, Max: 120"`
	TLS        interface{} `json:"tls,omitempty" jsonschema:"Use TLS encryption: true or false. Default: false"`
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
	if input.Port == 0 {
		input.Port = defaultPort
	}
	if input.Port < 1 || input.Port > 65535 {
		return errorResult(fmt.Sprintf("invalid port: %d (must be 1-65535)", input.Port))
	}
	if input.TimeoutSec <= 0 {
		input.TimeoutSec = defaultTimeoutSec
	}
	if input.TimeoutSec > maxTimeoutSec {
		return errorResult(fmt.Sprintf("timeout_sec exceeds maximum (%d)", maxTimeoutSec))
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

	timeout := time.Duration(input.TimeoutSec) * time.Second

	opts := &goredis.Options{
		Addr:         fmt.Sprintf("%s:%d", connectAddr, input.Port),
		Password:     input.Password,
		DB:           input.DB,
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	}

	if common.FlexBool(input.TLS) {
		opts.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

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

	result := formatResult(cmd)

	// Prepend SSRF warning if connecting to a private IP
	if ssrfWarning != "" {
		result = ssrfWarning + "\n\n" + result
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, RedisOutput{Result: result}, nil
}

// formatResult converts the Redis command result into a human-readable string.
func formatResult(cmd *goredis.Cmd) string {
	val := cmd.Val()

	switch v := val.(type) {
	case nil:
		return "(nil)\n"
	case string:
		return fmt.Sprintf("\"%s\"\n", v)
	case int64:
		return fmt.Sprintf("(integer) %d\n", v)
	case []interface{}:
		return formatSlice(v)
	default:
		return fmt.Sprintf("%v\n", v)
	}
}

// formatSlice formats a Redis array response with indexed elements.
func formatSlice(items []interface{}) string {
	if len(items) == 0 {
		return "(empty array)\n"
	}

	var sb strings.Builder
	for i, item := range items {
		switch v := item.(type) {
		case nil:
			sb.WriteString(fmt.Sprintf("%d) (nil)\n", i+1))
		case string:
			sb.WriteString(fmt.Sprintf("%d) \"%s\"\n", i+1, v))
		case int64:
			sb.WriteString(fmt.Sprintf("%d) (integer) %d\n", i+1, v))
		case []interface{}:
			sb.WriteString(fmt.Sprintf("%d) (array with %d elements)\n", i+1, len(v)))
		default:
			sb.WriteString(fmt.Sprintf("%d) %v\n", i+1, v))
		}
	}
	return sb.String()
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
Supports TLS encryption for secure connections.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, RedisOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, RedisOutput{}, nil
}
