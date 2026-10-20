package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// ValidateDatabaseTarget validates an explicit scan database path. It returns
// the absolute path and never creates or modifies the target.
func ValidateDatabaseTarget(path string, allowMissing bool) (string, error) {
	absolute, err := safeDatabasePath(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && allowMissing {
			return absolute, nil
		}
		return "", fmt.Errorf("inspect SQLite database %s: %w", absolute, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("SQLite database target is not a regular file: %s", absolute)
	}

	db, err := sql.Open("sqlite3", "file:"+absolute+"?mode=ro&_query_only=1&_busy_timeout=5000")
	if err != nil {
		return "", fmt.Errorf("open SQLite database for validation: %w", err)
	}
	defer db.Close()
	if err := validateExistingSchema(db); err != nil {
		return "", fmt.Errorf("validate Snablr SQLite database %s: %w", absolute, err)
	}
	return absolute, nil
}

// ResetDatabase clears only validated Snablr scan tables in one transaction.
// The database file and schema remain in place, so SQLite sidecars and file
// identity are not replaced or removed.
func ResetDatabase(path string) error {
	absolute, err := ValidateDatabaseTarget(path, false)
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite3", absolute)
	if err != nil {
		return fmt.Errorf("open SQLite database for reset: %w", err)
	}
	defer db.Close()
	for _, pragma := range []string{"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := db.Exec(pragma); err != nil {
			return fmt.Errorf("configure SQLite database for reset: %w", err)
		}
	}
	if err := initializeSchema(db); err != nil {
		return fmt.Errorf("prepare Snablr SQLite database for reset: %w", err)
	}
	if err := validateExistingSchema(db); err != nil {
		return fmt.Errorf("revalidate Snablr SQLite database before reset: %w", err)
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin SQLite reset transaction: %w", err)
	}
	for _, table := range []string{
		"bookmarks", "scope_exclusions", "access_observations", "members",
		"findings", "credentials", "correlations", "files", "shares",
		"targets", "scan_labels", "scans",
	} {
		if _, err := tx.Exec("DELETE FROM " + table); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("clear Snablr table %s: %w", table, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit SQLite reset transaction: %w", err)
	}
	return nil
}

func safeDatabasePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("SQLite database path cannot be empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve SQLite database path %q: %w", path, err)
	}
	absolute = filepath.Clean(absolute)
	if filepath.Base(absolute) == "." || filepath.Base(absolute) == string(filepath.Separator) {
		return "", fmt.Errorf("SQLite database path must name a file: %s", absolute)
	}
	if isProtectedDatabasePath(absolute) {
		return "", fmt.Errorf("refusing protected Snablr database path: %s", absolute)
	}
	if err := rejectSymlinkComponents(absolute); err != nil {
		return "", err
	}
	parent := filepath.Dir(absolute)
	if info, err := os.Stat(parent); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect SQLite database parent %s: %w", parent, err)
		}
	} else if !info.IsDir() {
		return "", fmt.Errorf("SQLite database parent is not a directory: %s", parent)
	}
	return absolute, nil
}

func isProtectedDatabasePath(path string) bool {
	protected := string(filepath.Separator) + filepath.Join("internal", "app", "snablr.db")
	return path == protected || strings.HasSuffix(path, protected)
}

func rejectSymlinkComponents(path string) error {
	volume := filepath.VolumeName(path)
	current := volume + string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(path, current), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return fmt.Errorf("inspect SQLite database path component %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing SQLite database path containing symlink: %s", current)
		}
	}
	return nil
}

func validateExistingSchema(db *sql.DB) error {
	var version string
	if err := db.QueryRow(`SELECT value FROM metadata WHERE key='schema_version'`).Scan(&version); err != nil {
		if strings.Contains(err.Error(), "no such table") || errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("missing Snablr schema metadata")
		}
		return fmt.Errorf("read schema metadata: %w", err)
	}
	if version != "1" && version != "2" {
		return fmt.Errorf("unsupported schema version %s", version)
	}
	for _, table := range []string{"metadata", "scans", "targets", "shares", "files", "access_observations", "members", "findings", "credentials", "correlations"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil {
			return fmt.Errorf("inspect table %s: %w", table, err)
		}
		if count != 1 {
			return fmt.Errorf("required table %s is missing", table)
		}
	}
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return fmt.Errorf("check integrity: %w", err)
	}
	if integrity != "ok" {
		return fmt.Errorf("integrity check failed: %s", integrity)
	}
	return nil
}
