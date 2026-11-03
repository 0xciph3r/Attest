// Package storetest helps tests prove that a failed operation left the
// database unchanged.
package storetest

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"testing"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// Tables are the tables holding security state.
var Tables = []string{
	"audit_entries", "policies", "nodes", "enrollment_challenges",
	"attest_challenges", "attestations", "identity_records",
}

// DumpDB renders every row of Tables in rowid order.
func DumpDB(t testing.TB, db *sql.DB) string {
	t.Helper()
	var out strings.Builder
	for _, table := range Tables {
		rows, err := db.Query(`SELECT * FROM ` + table + ` ORDER BY rowid`)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&out, "%s %v\n", table, vals)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		_ = rows.Close()
	}
	return out.String()
}

// Dump opens the database at path read-only and renders it with DumpDB.
func Dump(t testing.TB, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: path}).EscapedPath()+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	return DumpDB(t, db)
}
