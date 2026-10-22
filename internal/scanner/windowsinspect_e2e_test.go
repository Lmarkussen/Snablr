package scanner_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"snablr/internal/credentialanalysis"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/internal/store"
	"snablr/pkg/logx"
)

type windowsEndToEndSink struct{ state *store.SQLiteStore }

func (s windowsEndToEndSink) WriteFinding(f scanner.Finding) error { return s.state.RecordFinding(f) }
func (s windowsEndToEndSink) Close() error                         { return nil }
func (s windowsEndToEndSink) RecordCredentialCandidate(c credentialanalysis.Candidate) error {
	return s.state.RecordCredential(c)
}

func TestWindowsArtifactsUseLocalScanOrchestrationAndPersistence(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Groups.xml"), []byte(`<Groups><User name="one"/><User name="two"/></Groups>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "export.reg"), []byte("Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\Software\\Synthetic]\r\n\"SiteCode\"=\"ABC\"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "acceptance.db")
	state, err := store.Open(dbPath, store.Options{ScanID: "p6-local", SnablrVersion: "test", Semantics: "p6-tranche1", QueueSize: 16, BatchSize: 1, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sink := windowsEndToEndSink{state: state}
	engine := scanner.NewEngine(scanner.Options{Workers: 1, MaxFileSizeBytes: 1024 * 1024, MaxReadBytes: 1024 * 1024}, &rules.Manager{}, sink, logx.New("error"))
	if err := engine.Run(context.Background(), []string{root}); err != nil {
		t.Fatal(err)
	}
	if err := state.SetScanStatus(store.StatusCompleted, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", dbPath+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT payload FROM findings WHERE scan_id='p6-local' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var found map[string]scanner.Finding
	found = make(map[string]scanner.Finding)
	for rows.Next() {
		var payload []byte
		var finding scanner.Finding
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(payload, &finding); err != nil {
			t.Fatal(err)
		}
		found[finding.RuleID] = finding
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if found["windowsinspect.gpp.groups"].ObservationID == "" || found["windowsinspect.registry_export.structured"].MatchedText == "" {
		t.Fatalf("Windows findings did not survive orchestration/persistence: %#v", found)
	}
}
