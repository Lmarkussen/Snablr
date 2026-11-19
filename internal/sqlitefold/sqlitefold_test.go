package sqlitefold

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestContainsFoldsNonASCIILettersAndKeepsNULL(t *testing.T) {
	db, err := Open("snablr-sqlitefold-test", filepath.Join(t.TempDir(), "fold.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var upper, lower, literalPercent bool
	var null sql.NullBool
	err = db.QueryRow(`SELECT snablr_contains('ØKONOMI/LØNN', 'økonomi/lønn'), snablr_contains('åse.berg', 'ÅSE'), snablr_contains('report.txt', '%'), snablr_contains(NULL, 'x')`).Scan(&upper, &lower, &literalPercent, &null)
	if err != nil {
		t.Fatal(err)
	}
	if !upper || !lower {
		t.Fatalf("non-ASCII case folding failed: upper=%v lower=%v", upper, lower)
	}
	if literalPercent {
		t.Fatal("query metacharacters must be literal")
	}
	if null.Valid {
		t.Fatalf("NULL value must give NULL like LIKE does, got %v", null.Bool)
	}
}
