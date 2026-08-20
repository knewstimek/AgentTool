package mysql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

var registerLimitDriver sync.Once

type limitTestDriver struct{}
type limitTestConn struct{}
type limitTestRows struct{ row int }

func (limitTestDriver) Open(string) (driver.Conn, error)  { return limitTestConn{}, nil }
func (limitTestConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (limitTestConn) Close() error                        { return nil }
func (limitTestConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }
func (limitTestConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &limitTestRows{}, nil
}
func (*limitTestRows) Columns() []string { return []string{"first", "second", "third"} }
func (*limitTestRows) Close() error      { return nil }
func (r *limitTestRows) Next(dest []driver.Value) error {
	if r.row >= 20 {
		return io.EOF
	}
	dest[0] = strings.Repeat("가", 50)
	dest[1] = "value"
	dest[2] = "hidden"
	r.row++
	return nil
}

func TestFormatValueUsesRuneLimit(t *testing.T) {
	got := formatValue(strings.Repeat("가", 20), 10)
	if !utf8.ValidString(got) || utf8.RuneCountInString(got) != 10 {
		t.Fatalf("invalid bounded value %q (%d runes)", got, utf8.RuneCountInString(got))
	}
}

func TestExecuteQueryBoundsRowsColumnsCellsAndTotalOutput(t *testing.T) {
	registerLimitDriver.Do(func() { sql.Register("agent-tool-limit-test", limitTestDriver{}) })
	db, err := sql.Open("agent-tool-limit-test", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	got, err := executeQuery(context.Background(), db, "SELECT anything", queryLimits{
		maxRows: 5, maxColumns: 2, maxValueChars: 10, maxOutputChars: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "third") || !strings.Contains(got, "2/3 columns displayed") {
		t.Fatalf("column limit not reported:\n%s", got)
	}
	if !strings.Contains(got, "(5 rows displayed") {
		t.Fatalf("row limit was not enforced or reported:\n%s", got)
	}

	got, err = executeQuery(context.Background(), db, "SELECT anything", queryLimits{
		maxRows: 20, maxColumns: 2, maxValueChars: 10, maxOutputChars: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if utf8.RuneCountInString(got) > 100 || !strings.Contains(got, "Output truncated") {
		t.Fatalf("total output limit not enforced: %d runes\n%s", utf8.RuneCountInString(got), got)
	}
}
