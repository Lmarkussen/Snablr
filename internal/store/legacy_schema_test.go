package store

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"snablr/internal/scanner"
)

// schemaThreeSQL is the schema of databases written before findings kept
// large evidence in the evidence table.
const schemaThreeSQL = `
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scans (scan_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL, snablr_version TEXT, semantics TEXT, started_at TEXT NOT NULL, ended_at TEXT, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scan_labels (scan_id TEXT PRIMARY KEY, display_id TEXT NOT NULL UNIQUE, FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS targets (scan_id TEXT NOT NULL, host TEXT NOT NULL, status TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (scan_id, host), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS shares (scan_id TEXT NOT NULL, host TEXT NOT NULL, share TEXT NOT NULL, status TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (scan_id, host, share), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS files (scan_id TEXT NOT NULL, file_key TEXT NOT NULL, host TEXT NOT NULL, share TEXT NOT NULL, path TEXT NOT NULL, size INTEGER NOT NULL, modified_at TEXT, first_seen TEXT, last_seen TEXT, updated_at TEXT NOT NULL, status TEXT NOT NULL, semantics TEXT NOT NULL, PRIMARY KEY (scan_id, file_key), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS access_observations (scan_id TEXT NOT NULL, context_id TEXT NOT NULL, file_key TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, access_result TEXT NOT NULL, PRIMARY KEY (scan_id, context_id, file_key), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS members (scan_id TEXT NOT NULL, parent_key TEXT NOT NULL, member_key TEXT NOT NULL, member_type TEXT NOT NULL, member_path TEXT NOT NULL, status TEXT NOT NULL, provenance TEXT, PRIMARY KEY (scan_id, parent_key, member_key), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL, fingerprint TEXT NOT NULL, host TEXT, share TEXT, path TEXT, rule_id TEXT, category TEXT, payload TEXT NOT NULL, UNIQUE(scan_id, fingerprint), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS credentials (id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL, credential_key TEXT NOT NULL, credential_type TEXT, identity TEXT, value TEXT, payload TEXT NOT NULL, UNIQUE(scan_id, credential_key), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS correlations (scan_id TEXT NOT NULL, correlation_key TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY (scan_id, correlation_key), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS derived_findings (id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL, correlation_key TEXT NOT NULL, payload TEXT NOT NULL, UNIQUE(scan_id, correlation_key), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS correlation_state (id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL, family TEXT NOT NULL, group_key TEXT NOT NULL, slot TEXT NOT NULL, priority INTEGER NOT NULL, severity_rank INTEGER NOT NULL, file_path TEXT NOT NULL, payload TEXT NOT NULL, FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS derived_state (scan_id TEXT PRIMARY KEY, status TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT, FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS bookmarks (scan_id TEXT NOT NULL, file_key TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (scan_id, file_key), FOREIGN KEY (scan_id, file_key) REFERENCES files(scan_id, file_key));
CREATE TABLE IF NOT EXISTS scope_exclusions (scan_id TEXT NOT NULL, kind TEXT NOT NULL, host TEXT NOT NULL, share TEXT NOT NULL, path TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (scan_id, kind, host, share, path), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE INDEX IF NOT EXISTS files_status_idx ON files(scan_id, status);
CREATE INDEX IF NOT EXISTS files_identity_idx ON files(scan_id, host, share, path);
CREATE INDEX IF NOT EXISTS findings_path_idx ON findings(scan_id, path);
CREATE INDEX IF NOT EXISTS findings_scan_id_id_idx ON findings(scan_id, id);
CREATE INDEX IF NOT EXISTS derived_findings_scan_id_id_idx ON derived_findings(scan_id, id);
CREATE INDEX IF NOT EXISTS correlation_state_group_idx ON correlation_state(scan_id, family, group_key, slot, priority DESC, severity_rank DESC, file_path, id);
CREATE INDEX IF NOT EXISTS credentials_scan_id_id_idx ON credentials(scan_id, id);
CREATE INDEX IF NOT EXISTS credentials_group_idx ON credentials(scan_id, credential_type, identity, value, id);
CREATE INDEX IF NOT EXISTS bookmarks_scan_created_idx ON bookmarks(scan_id, created_at, file_key);
CREATE INDEX IF NOT EXISTS scope_exclusions_identity_idx ON scope_exclusions(scan_id, kind, host, share, path);
INSERT INTO metadata(key, value) VALUES ('schema_version', '3') ON CONFLICT(key) DO UPDATE SET value=excluded.value;
`

// createSchemaThreeDatabase writes a database as a schema 3 build left it.
func createSchemaThreeDatabase(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schemaThreeSQL); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	return db
}

// A schema 3 database keeps every finding and correlation candidate, payload
// unchanged, after migration; new findings in it keep large evidence once.
func TestSchemaThreeDatabaseMigratesToSharedEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db := createSchemaThreeDatabase(t, path)
	evidence := strings.Repeat("Server=db.example.test;Database=Legacy;\n", 1024)
	legacy := scanner.Finding{RuleID: "synthetic.legacy", FilePath: "legacy.json", Host: "fileserver.example.test", Share: "share", Match: "legacy", MatchedText: evidence, Snippet: evidence, Context: evidence}
	legacyPayload, _ := json.Marshal(legacy)
	started := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO scans(scan_id,schema_version,snablr_version,semantics,started_at,status) VALUES('legacy-scan',3,'old','semantics-synthetic',?,'completed')`, started); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO findings(scan_id,fingerprint,host,share,path,rule_id,category,payload) VALUES('legacy-scan',?,?,?,?,?,?,?)`, payloadFingerprint(legacyPayload), legacy.Host, legacy.Share, legacy.FilePath, legacy.RuleID, legacy.Category, legacyPayload); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO correlation_state(scan_id,family,group_key,slot,priority,severity_rank,file_path,payload) VALUES('legacy-scan','backup','group','slot',1,1,'legacy.json',?)`, legacyPayload); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	state, err := Open(path, Options{ScanID: "legacy-scan", Semantics: "semantics-synthetic", BatchSize: 1, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	var version string
	if err := state.db.QueryRow(`SELECT value FROM metadata WHERE key='schema_version'`).Scan(&version); err != nil || version != "4" {
		t.Fatalf("schema version=%q err=%v, want 4", version, err)
	}
	var payload []byte
	if err := state.db.QueryRow(`SELECT payload FROM findings WHERE scan_id='legacy-scan'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if string(payload) != string(legacyPayload) {
		t.Fatal("migrated finding payload changed")
	}
	if err := state.db.QueryRow(`SELECT payload FROM correlation_state WHERE scan_id='legacy-scan'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if string(payload) != string(legacyPayload) {
		t.Fatal("migrated correlation candidate payload changed")
	}

	fresh := legacy
	fresh.FilePath, fresh.Match = "fresh.json", "fresh"
	if err := state.RecordFinding(fresh); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	var refs sql.NullString
	if err := state.db.QueryRow(`SELECT payload, evidence_refs FROM finding_rows WHERE path='fresh.json'`).Scan(&stored, &refs); err != nil {
		t.Fatal(err)
	}
	if !refs.Valid || strings.Contains(string(stored), "Database=Legacy") {
		t.Fatalf("new finding kept its evidence inline in a migrated database (refs=%v)", refs)
	}
	var found []scanner.Finding
	if err := state.IterateFindings(t.Context(), 16, func(batch []scanner.Finding) error {
		found = append(found, batch...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 || found[0].MatchedText != evidence || found[1].MatchedText != evidence || found[1].Context != evidence {
		t.Fatalf("findings after migration: %d", len(found))
	}
}
