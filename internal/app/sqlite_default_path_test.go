package app

import "testing"

func TestDefaultSQLiteStatePathMatchesScanFallback(t *testing.T) {
	if got := DefaultSQLiteStatePath(); got != "snablr.db" {
		t.Fatalf("default SQLite path=%q, want snablr.db", got)
	}
}
