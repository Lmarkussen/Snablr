package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestValidateDatabaseTargetRejectsUnsafeAndIncompatibleTargets(t *testing.T) {
	temp := t.TempDir()
	missing := filepath.Join(temp, "new.db")
	if got, err := ValidateDatabaseTarget(missing, true); err != nil || got != missing {
		t.Fatalf("missing target validation = %q, %v", got, err)
	}
	if _, err := ValidateDatabaseTarget(filepath.Join(temp, "missing.db"), false); err == nil {
		t.Fatal("expected missing target to be rejected when creation is not allowed")
	}
	if _, err := ValidateDatabaseTarget(temp, true); err == nil {
		t.Fatal("expected directory target rejection")
	}
	incompatible := filepath.Join(temp, "not-snablr.db")
	if err := os.WriteFile(incompatible, []byte("not sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateDatabaseTarget(incompatible, true); err == nil {
		t.Fatal("expected incompatible database rejection")
	}
	protected := filepath.Join(temp, "internal", "app", "snablr.db")
	if _, err := ValidateDatabaseTarget(protected, true); err == nil {
		t.Fatal("expected protected database rejection")
	}
	link := filepath.Join(temp, "link.db")
	if err := os.Symlink(missing, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateDatabaseTarget(link, true); err == nil {
		t.Fatal("expected symlink target rejection")
	}
}

func TestResetDatabaseClearsSnablrDataWithoutReplacingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reset.db")
	state, err := Open(path, Options{ScanID: "legacy-internal", ScanDomain: "domain.local", Semantics: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.RecordTarget("host", "completed", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ResetDatabase(path); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("reset replaced the database file")
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, table := range []string{"scans", "targets", "scan_labels"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("reset left %d rows in %s", count, table)
		}
	}
}

func TestDisplayIDsPersistPerDatabaseAndAvoidConcurrentCollisions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labels.db")
	const workers = 5
	var group sync.WaitGroup
	errorsCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			state, err := Open(path, Options{ScanID: "internal-" + string(rune('a'+i)), ScanDomain: "DOMAIN.LOCAL", Semantics: "test", BatchSize: 1})
			if err != nil {
				errorsCh <- err
				return
			}
			errorsCh <- state.Close()
		}(i)
	}
	group.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT display_id FROM scan_labels ORDER BY display_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var labels []string
	for rows.Next() {
		var label string
		if err := rows.Scan(&label); err != nil {
			t.Fatal(err)
		}
		labels = append(labels, label)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(labels) != workers {
		t.Fatalf("got %d labels, want %d: %v", len(labels), workers, labels)
	}
	for i, want := range []string{"scan-domain.local-001", "scan-domain.local-002", "scan-domain.local-003", "scan-domain.local-004", "scan-domain.local-005"} {
		if labels[i] != want {
			t.Fatalf("label[%d]=%q, want %q", i, labels[i], want)
		}
	}
	state, err := Open(path, Options{ScanID: "internal-restart", ScanDomain: "domain.local", Semantics: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := db.QueryRow(`SELECT display_id FROM scan_labels WHERE scan_id=?`, "internal-restart").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "scan-domain.local-006" {
		t.Fatalf("restart label=%q, want scan-domain.local-006", got)
	}
}

func TestLegacyScanKeepsInternalLookupAndUsesFallbackDisplayID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	state, err := Open(path, Options{ScanID: "scan-1700000000000000000", Semantics: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate a historical row by removing only its optional label.
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM scan_labels WHERE scan_id=?`, "scan-1700000000000000000"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := ValidateDatabaseTarget(path, false); err != nil {
		t.Fatal(err)
	}
}
