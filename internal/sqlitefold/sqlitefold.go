// Package sqlitefold provides the case-insensitive substring match used by
// search. SQLite's LIKE and COLLATE NOCASE fold only ASCII letters, so a
// search for "ø" never matched "Ø" (or "Å", "Æ", "É", ...).
package sqlitefold

import (
	"database/sql"
	"strings"
	"sync"

	sqlite3 "github.com/mattn/go-sqlite3"
)

// FunctionName is the SQL function registered by Register:
// snablr_contains(value, query) is true when value contains query, ignoring
// case for every Unicode letter, and NULL when value is NULL (like LIKE).
const FunctionName = "snablr_contains"

// ContainsFold reports whether value contains query, ignoring case.
func ContainsFold(value, query string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(query))
}

// Register adds snablr_contains to a SQLite connection.
func Register(conn *sqlite3.SQLiteConn) error {
	return conn.RegisterFunc(FunctionName, func(value any, query string) any {
		switch typed := value.(type) {
		case nil:
			return nil
		case string:
			return ContainsFold(typed, query)
		case []byte:
			if typed == nil { // the driver passes SQL NULL as a nil []byte
				return nil
			}
			return ContainsFold(string(typed), query)
		default:
			return false
		}
	}, true)
}

var (
	registerMu sync.Mutex
	registered = map[string]bool{}
)

// Open opens a database through a driver whose connections have
// snablr_contains. Each driverName is registered once.
func Open(driverName, dataSourceName string) (*sql.DB, error) {
	registerMu.Lock()
	if !registered[driverName] {
		sql.Register(driverName, &sqlite3.SQLiteDriver{ConnectHook: Register})
		registered[driverName] = true
	}
	registerMu.Unlock()
	return sql.Open(driverName, dataSourceName)
}
