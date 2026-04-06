package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"agent-tool/common"

	"github.com/go-sql-driver/mysql"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultPort       = 3306
	defaultTimeoutSec = 30
	maxTimeoutSec     = 120
	maxRows           = 1000
	maxValueLen       = 200
)

type MySQLInput struct {
	Host       string `json:"host" jsonschema:"MySQL server hostname or IP address,required"`
	Port       interface{} `json:"port,omitempty" jsonschema:"MySQL port number. Default: 3306"`
	User       string `json:"user" jsonschema:"MySQL username,required"`
	Password   string `json:"password,omitempty" jsonschema:"Password for authentication"`
	Database   string `json:"database,omitempty" jsonschema:"Database name to connect to"`
	Query      string `json:"query" jsonschema:"SQL query to execute,required"`
	TimeoutSec interface{} `json:"timeout_sec,omitempty" jsonschema:"Query timeout in seconds. Default: 30, Max: 120"`
}

type MySQLOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input MySQLInput) (*mcp.CallToolResult, MySQLOutput, error) {
	// Validate required fields
	input.Host = strings.TrimSpace(input.Host)
	if input.Host == "" {
		return errorResult("host is required")
	}
	input.User = strings.TrimSpace(input.User)
	if input.User == "" {
		return errorResult("user is required")
	}
	input.Query = strings.TrimSpace(input.Query)
	if input.Query == "" {
		return errorResult("query is required")
	}

	// Defaults
	port, ok := common.FlexInt(input.Port)
	if !ok {
		return errorResult("port must be an integer")
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

	// SSRF policy: cloud metadata always blocked. Private IPs allowed by default
	// (configurable via set_config allow_mysql_private). Warning shown on every
	// private IP access to help detect prompt injection attacks.
	// Use resolved IP for connection to prevent DNS rebinding (TOCTOU).
	// CheckHostSSRF resolves DNS and validates; we connect to the validated IP.
	resolvedIP, ssrfWarning, ssrfErr := common.CheckHostSSRF(ctx, input.Host, common.GetAllowMySQLPrivate(), "mysql")
	if ssrfErr != nil {
		return errorResult(ssrfErr.Error())
	}
	connectAddr := input.Host
	if resolvedIP != "" {
		connectAddr = resolvedIP
	}

	timeout := time.Duration(timeoutSec) * time.Second

	// Use mysql.Config struct to safely build DSN — prevents parameter injection
	// via database/user fields containing '?', '&', '@', or ':' characters.
	cfg := mysql.Config{
		User:                 input.User,
		Passwd:               input.Password,
		Net:                  "tcp",
		Addr:                 fmt.Sprintf("%s:%d", connectAddr, port),
		DBName:               input.Database,
		Timeout:              timeout,
		ReadTimeout:          timeout,
		WriteTimeout:         timeout,
		ParseTime:            true,
		MultiStatements:      false,
		AllowNativePasswords: true,
	}
	dsn := cfg.FormatDSN()

	opCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to open connection: %s", sanitizeError(err, input.Password)))
	}
	defer db.Close()

	// Single connection, no pooling — security best practice
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	if err := db.PingContext(opCtx); err != nil {
		return errorResult(fmt.Sprintf("connection failed: %s", sanitizeError(err, input.Password)))
	}

	// Detect query type to choose between Query and Exec
	queryUpper := strings.ToUpper(strings.TrimSpace(input.Query))
	isSelect := strings.HasPrefix(queryUpper, "SELECT") ||
		strings.HasPrefix(queryUpper, "SHOW") ||
		strings.HasPrefix(queryUpper, "DESCRIBE") ||
		strings.HasPrefix(queryUpper, "EXPLAIN")

	var result string
	if isSelect {
		result, err = executeQuery(opCtx, db, input.Query)
	} else {
		result, err = executeExec(opCtx, db, input.Query)
	}
	if err != nil {
		return errorResult(fmt.Sprintf("query failed: %s", sanitizeError(err, input.Password)))
	}

	// Prepend SSRF warning if connecting to a private IP
	if ssrfWarning != "" {
		result = ssrfWarning + "\n\n" + result
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, MySQLOutput{Result: result}, nil
}

// executeQuery runs a SELECT-like query and returns formatted table output.
func executeQuery(ctx context.Context, db *sql.DB, query string) (string, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return "", fmt.Errorf("get columns: %w", err)
	}

	// Read all rows (up to maxRows)
	var allRows [][]string
	scanDest := make([]interface{}, len(cols))
	scanPtrs := make([]interface{}, len(cols))
	for i := range scanDest {
		scanPtrs[i] = &scanDest[i]
	}

	rowCount := 0
	truncated := false
	for rows.Next() {
		if rowCount >= maxRows {
			truncated = true
			break
		}
		if err := rows.Scan(scanPtrs...); err != nil {
			return "", fmt.Errorf("scan row: %w", err)
		}

		row := make([]string, len(cols))
		for i, v := range scanDest {
			row[i] = formatValue(v)
		}
		allRows = append(allRows, row)
		rowCount++
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	// Calculate column widths for alignment
	widths := make([]int, len(cols))
	for i, col := range cols {
		widths[i] = utf8.RuneCountInString(col)
	}
	for _, row := range allRows {
		for i, val := range row {
			vlen := utf8.RuneCountInString(val)
			if vlen > widths[i] {
				widths[i] = vlen
			}
		}
	}

	// Build formatted table
	var sb strings.Builder

	// Header
	for i, col := range cols {
		if i > 0 {
			sb.WriteString(" | ")
		}
		sb.WriteString(padRight(col, widths[i]))
	}
	sb.WriteString("\n")

	// Separator
	for i, w := range widths {
		if i > 0 {
			sb.WriteString("-+-")
		}
		sb.WriteString(strings.Repeat("-", w))
	}
	sb.WriteString("\n")

	// Rows
	for _, row := range allRows {
		for i, val := range row {
			if i > 0 {
				sb.WriteString(" | ")
			}
			sb.WriteString(padRight(val, widths[i]))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("\n(%d rows", rowCount))
	if truncated {
		sb.WriteString(fmt.Sprintf(", truncated at %d", maxRows))
	}
	sb.WriteString(")\n")

	return sb.String(), nil
}

// executeExec runs a non-SELECT query and returns affected rows info.
func executeExec(ctx context.Context, db *sql.DB, query string) (string, error) {
	result, err := db.ExecContext(ctx, query)
	if err != nil {
		return "", err
	}

	affected, _ := result.RowsAffected()
	lastID, _ := result.LastInsertId()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Rows affected: %d\n", affected))
	if lastID > 0 {
		sb.WriteString(fmt.Sprintf("Last insert ID: %d\n", lastID))
	}

	return sb.String(), nil
}

// formatValue converts a scanned SQL value to a display string.
func formatValue(v interface{}) string {
	if v == nil {
		return "NULL"
	}

	var s string
	switch val := v.(type) {
	case []byte:
		s = string(val)
	case time.Time:
		s = val.Format("2006-01-02 15:04:05")
	default:
		s = fmt.Sprintf("%v", val)
	}

	// Truncate long values
	if utf8.RuneCountInString(s) > maxValueLen {
		runes := []rune(s)
		s = string(runes[:maxValueLen]) + "..."
	}
	return s
}

// padRight pads a string with spaces to reach the target width.
func padRight(s string, width int) string {
	n := utf8.RuneCountInString(s)
	if n >= width {
		return s
	}
	return s + strings.Repeat(" ", width-n)
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
		Name: "mysql",
		Description: `Execute SQL queries on a MySQL/MariaDB database.
Supports SELECT, INSERT, UPDATE, DELETE, SHOW, DESCRIBE, and other SQL statements.
SELECT-like queries return formatted table output with column alignment.
Non-SELECT queries return affected row count and last insert ID.
Connection is closed after each call (no session pooling).
Max 1000 rows returned, long values truncated at 200 characters.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, MySQLOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, MySQLOutput{}, nil
}
