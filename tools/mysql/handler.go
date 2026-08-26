package mysql

import (
	"context"
	"crypto/tls"
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
	defaultPort           = 3306
	defaultTimeoutSec     = 30
	maxTimeoutSec         = 120
	defaultMaxRows        = 1000
	defaultCharset        = "utf8mb4"
	hardMaxRows           = 10000
	defaultMaxColumns     = 100
	hardMaxColumns        = 1000
	defaultMaxValueChars  = 200
	hardMaxValueChars     = 10000
	defaultMaxOutputChars = common.DefaultOutputChars
	hardMaxOutputChars    = common.HardOutputChars
)

type MySQLInput struct {
	Host           string      `json:"host" jsonschema:"MySQL server hostname or IP address,required"`
	Port           interface{} `json:"port,omitempty" jsonschema:"MySQL port number. Default: 3306"`
	User           string      `json:"user" jsonschema:"MySQL username,required"`
	Password       string      `json:"password,omitempty" jsonschema:"Password for authentication"`
	Database       string      `json:"database,omitempty" jsonschema:"Database name to connect to"`
	Query          string      `json:"query" jsonschema:"SQL query to execute,required"`
	TimeoutSec     interface{} `json:"timeout_sec,omitempty" jsonschema:"Query timeout in seconds. Default: 30, Max: 120"`
	TLS            interface{} `json:"tls,omitempty" jsonschema:"Use verified TLS encryption: true or false. Default: false"`
	MaxRows        int         `json:"max_rows,omitempty" jsonschema:"Maximum rows returned by SELECT-like queries. Default: 1000, Max: 10000"`
	MaxColumns     int         `json:"max_columns,omitempty" jsonschema:"Maximum columns displayed. Default: 100, Max: 1000"`
	MaxValueChars  int         `json:"max_value_chars,omitempty" jsonschema:"Maximum characters displayed per cell. Default: 200, Max: 10000"`
	MaxOutputChars int         `json:"max_output_chars,omitempty" jsonschema:"Maximum total returned text characters. Default: 32768, Max: 131072"`
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
	if input.MaxRows <= 0 {
		input.MaxRows = defaultMaxRows
	}
	if input.MaxRows > hardMaxRows {
		return errorResult(fmt.Sprintf("max_rows must be at most %d", hardMaxRows))
	}
	if input.MaxColumns <= 0 {
		input.MaxColumns = defaultMaxColumns
	}
	if input.MaxColumns > hardMaxColumns {
		return errorResult(fmt.Sprintf("max_columns must be at most %d", hardMaxColumns))
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

	// Configure the connection directly instead of relying on the server's
	// session defaults. AgentTool queries are UTF-8, so every new connection
	// must declare utf8mb4 before it executes user SQL.
	cfg := mysql.NewConfig()
	cfg.User = input.User
	cfg.Passwd = input.Password
	cfg.Net = "tcp"
	cfg.Addr = fmt.Sprintf("%s:%d", connectAddr, port)
	cfg.DBName = input.Database
	cfg.Timeout = timeout
	cfg.ReadTimeout = timeout
	cfg.WriteTimeout = timeout
	cfg.ParseTime = true
	cfg.MultiStatements = false
	cfg.AllowNativePasswords = true
	configureTLS(cfg, input.Host, common.FlexBool(input.TLS))
	if err := configureCharset(cfg); err != nil {
		return errorResult(fmt.Sprintf("failed to configure connection charset: %s", err))
	}

	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to configure connection: %s", sanitizeError(err, input.Password)))
	}

	opCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	db := sql.OpenDB(connector)
	defer db.Close()

	// Single connection, no pooling — security best practice
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	if err := db.PingContext(opCtx); err != nil {
		return errorResult(fmt.Sprintf("connection failed: %s", sanitizeError(err, input.Password)))
	}

	// Detect query type to choose between Query and Exec
	var result string
	if queryReturnsRows(input.Query) {
		result, err = executeQuery(opCtx, db, input.Query, queryLimits{
			maxRows: input.MaxRows, maxColumns: input.MaxColumns,
			maxValueChars: input.MaxValueChars, maxOutputChars: input.MaxOutputChars,
		})
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

func configureCharset(cfg *mysql.Config) error {
	return cfg.Apply(mysql.Charset(defaultCharset, ""))
}

func configureTLS(cfg *mysql.Config, host string, enabled bool) {
	if enabled {
		cfg.TLS = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: host,
		}
	}
}

func queryReturnsRows(query string) bool {
	keywords := topLevelSQLKeywords(query)
	if len(keywords) == 0 {
		return false
	}

	statement := keywords[0]
	if statement == "WITH" {
		statement = ""
		for _, keyword := range keywords[1:] {
			switch keyword {
			case "SELECT", "INSERT", "UPDATE", "DELETE", "REPLACE":
				statement = keyword
			}
			if statement != "" {
				break
			}
		}
	}

	switch statement {
	case "SELECT", "SHOW", "DESCRIBE", "DESC", "EXPLAIN", "TABLE", "VALUES",
		"CALL", "HELP", "ANALYZE", "CHECK", "OPTIMIZE", "REPAIR":
		return true
	case "INSERT", "UPDATE", "DELETE", "REPLACE":
		for _, keyword := range keywords[1:] {
			if keyword == "RETURNING" {
				return true
			}
		}
	}
	return false
}

func topLevelSQLKeywords(query string) []string {
	var keywords []string
	depth := 0
	for i := 0; i < len(query); {
		switch {
		case query[i] == '#' || (query[i] == '-' && i+1 < len(query) && query[i+1] == '-'):
			for i < len(query) && query[i] != '\n' {
				i++
			}
		case query[i] == '/' && i+1 < len(query) && query[i+1] == '*':
			i += 2
			for i+1 < len(query) && !(query[i] == '*' && query[i+1] == '/') {
				i++
			}
			if i+1 < len(query) {
				i += 2
			}
		case query[i] == '\'' || query[i] == '"' || query[i] == '`':
			quote := query[i]
			i++
			for i < len(query) {
				if query[i] == '\\' && i+1 < len(query) {
					i += 2
					continue
				}
				if query[i] == quote {
					if i+1 < len(query) && query[i+1] == quote {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
		case query[i] == '(':
			depth++
			i++
		case query[i] == ')':
			if depth > 0 {
				depth--
			}
			i++
		case depth == 0 && isSQLWordStart(query[i]):
			start := i
			for i < len(query) && isSQLWordPart(query[i]) {
				i++
			}
			keywords = append(keywords, strings.ToUpper(query[start:i]))
		default:
			i++
		}
	}
	return keywords
}

func isSQLWordStart(ch byte) bool {
	return ch == '_' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z'
}

func isSQLWordPart(ch byte) bool {
	return isSQLWordStart(ch) || ch >= '0' && ch <= '9' || ch == '$'
}

// executeQuery runs a SELECT-like query and returns formatted table output.
type queryLimits struct {
	maxRows        int
	maxColumns     int
	maxValueChars  int
	maxOutputChars int
}

func executeQuery(ctx context.Context, db *sql.DB, query string, limits queryLimits) (string, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return "", fmt.Errorf("get columns: %w", err)
	}

	displayColumns := len(cols)
	if displayColumns > limits.maxColumns {
		displayColumns = limits.maxColumns
	}
	displayCols := make([]string, displayColumns)
	for i := range displayCols {
		displayCols[i], _ = common.TruncateRunes(cols[i], limits.maxValueChars, "…")
	}

	// Read only enough formatted data to satisfy both the row and output budgets.
	var allRows [][]string
	scanDest := make([]interface{}, len(cols))
	scanPtrs := make([]interface{}, len(cols))
	for i := range scanDest {
		scanPtrs[i] = &scanDest[i]
	}

	rowCount := 0
	truncated := false
	estimatedChars := 0
	for rows.Next() {
		if rowCount >= limits.maxRows {
			truncated = true
			break
		}
		if err := rows.Scan(scanPtrs...); err != nil {
			return "", fmt.Errorf("scan row: %w", err)
		}

		row := make([]string, displayColumns)
		rowChars := 1
		for i := 0; i < displayColumns; i++ {
			row[i] = formatValue(scanDest[i], limits.maxValueChars)
			rowChars += utf8.RuneCountInString(row[i]) + 3
		}
		if rowCount > 0 && estimatedChars+rowChars > limits.maxOutputChars*2 {
			truncated = true
			break
		}
		allRows = append(allRows, row)
		estimatedChars += rowChars
		rowCount++
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	// Calculate column widths for alignment
	widths := make([]int, len(displayCols))
	for i, col := range displayCols {
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

	// Build formatted table. Rows are appended atomically so a continuation
	// hint never follows a half-written SQL row.
	var sb strings.Builder
	usedChars := 0

	var header strings.Builder
	for i, col := range displayCols {
		if i > 0 {
			header.WriteString(" | ")
		}
		header.WriteString(padRight(col, widths[i]))
	}
	header.WriteString("\n")

	var separator strings.Builder
	for i, w := range widths {
		if i > 0 {
			separator.WriteString("-+-")
		}
		separator.WriteString(strings.Repeat("-", w))
	}
	separator.WriteString("\n")
	common.AppendWithinRuneBudget(&sb, &usedChars, header.String(), limits.maxOutputChars)
	common.AppendWithinRuneBudget(&sb, &usedChars, separator.String(), limits.maxOutputChars)

	displayedRows := 0
	for _, row := range allRows {
		var line strings.Builder
		for i, val := range row {
			if i > 0 {
				line.WriteString(" | ")
			}
			line.WriteString(padRight(val, widths[i]))
		}
		line.WriteString("\n")
		if !common.AppendWithinRuneBudget(&sb, &usedChars, line.String(), limits.maxOutputChars) {
			truncated = true
			break
		}
		displayedRows++
	}

	sb.WriteString(fmt.Sprintf("\n(%d rows displayed", displayedRows))
	if len(cols) > displayColumns {
		sb.WriteString(fmt.Sprintf(", %d/%d columns displayed", displayColumns, len(cols)))
	}
	if truncated {
		sb.WriteString(", output truncated; use SQL LIMIT/OFFSET, select fewer columns, or adjust output limits")
	}
	sb.WriteString(")\n")

	result, _ := common.TruncateRunes(sb.String(), limits.maxOutputChars, "\n[Output truncated; use SQL LIMIT/OFFSET or select fewer columns]")
	return result, nil
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
func formatValue(v interface{}, maxValueChars int) string {
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
	s, _ = common.TruncateRunes(s, maxValueChars, "…")
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
Each connection uses utf8mb4 for client, connection, and result text.
Verified TLS connections are available with tls=true.
Defaults: 1000 rows, 100 columns, 200 characters per cell, and 32768 total output characters.
Use max_rows/max_columns/max_value_chars/max_output_chars to tune bounded output;
use SQL LIMIT/OFFSET for deterministic paging.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, MySQLOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, MySQLOutput{}, nil
}
