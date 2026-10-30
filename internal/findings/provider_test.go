package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
	"snablr/internal/store"
)

func makeFixtureDB(t *testing.T, scanIDs ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "snablr.db")
	for i, scanID := range scanIDs {
		state, err := store.Open(path, store.Options{ScanID: scanID, SnablrVersion: "test", Semantics: "synthetic", QueueSize: 8, BatchSize: 1, FlushEvery: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		finding := scanner.Finding{RuleID: "synthetic.rule", RuleName: "Synthetic evidence", Severity: "high", Confidence: "high", Actionable: true, Host: "HOST", Share: "Share", FilePath: "evidence.txt", MatchedText: "synthetic-value"}
		if err := state.RecordFinding(finding); err != nil {
			t.Fatal(err)
		}
		if err := state.RecordCredential(credentialanalysis.Candidate{CredentialType: "password", Identity: "synthetic-user", Value: "SyntheticPassword!", Verification: credentialanalysis.Confirmed, Host: "HOST", Share: "Share", Path: "evidence.txt"}); err != nil {
			t.Fatal(err)
		}
		if err := state.SetScanStatus(store.StatusCompleted, time.Date(2026, 1, i+1, 12, 0, 0, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
		if err := state.Flush(); err != nil {
			t.Fatal(err)
		}
		if err := state.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestCredentialByIDRestoresAuthoritativeValue(t *testing.T) {
	path := makeFixtureDB(t, "credential-by-id")
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()

	credentials, err := provider.Credentials(context.Background(), "credential-by-id", 0, 10)
	if err != nil || len(credentials) != 1 {
		t.Fatalf("credentials = %#v, err = %v", credentials, err)
	}
	id := credentials[0].ID
	credential, err := provider.CredentialByID(context.Background(), "credential-by-id", id)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Candidate.Identity != "synthetic-user" || credential.Candidate.Value != "SyntheticPassword!" {
		t.Fatalf("credential by id lost recovered values: %#v", credential.Candidate)
	}
}

func TestGlobalSearchFindsPersistedFilenameEvidenceCredentialAndLiteralText(t *testing.T) {
	path := makeFixtureDB(t, "global-search")
	p, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, query := range []string{"evidence.txt", "synthetic-value", "synthetic-user", "SyntheticPassword!", "synthetic", "SYNTHETIC"} {
		rows, err := p.GlobalSearch(context.Background(), "global-search", query, globalSearchPageSize, 0)
		if err != nil {
			t.Fatalf("search %q: %v", query, err)
		}
		if len(rows) == 0 {
			t.Fatalf("search %q returned no persisted records", query)
		}
	}
	for _, literal := range []string{"%", "_", "'", "!"} {
		// Searches are literal: metacharacters may return real matches but must
		// never be parsed as SQL syntax or cause an error.
		if _, err := p.GlobalSearch(context.Background(), "global-search", literal, globalSearchPageSize, 0); err != nil {
			t.Fatalf("literal search %q: %v", literal, err)
		}
	}
}

func TestGlobalSearchPaginatesPastFiveHundredFindings(t *testing.T) {
	path := makeFixtureDB(t, "global-search-pages")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 510; i++ {
		name := fmt.Sprintf("/fixture/deepterm-%03d-æøå_%%.cfg", i)
		payload := fmt.Sprintf(`{"rule_id":"fixture.rule","category":"test","file_path":%q}`, name)
		if _, err := db.Exec(`INSERT INTO findings(scan_id,fingerprint,payload,path,rule_id,category,host,share) VALUES(?,?,?,?,?,?,?,?)`, "global-search-pages", fmt.Sprintf("fingerprint-%03d", i), payload, name, "fixture.rule", "test", "host", "share"); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	first, err := p.GlobalSearch(context.Background(), "global-search-pages", "deepterm", globalSearchPageSize, 0)
	if err != nil {
		t.Fatal(err)
	}
	last, err := p.GlobalSearch(context.Background(), "global-search-pages", "deepterm", globalSearchPageSize, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 5 || len(last) != 5 {
		t.Fatalf("page sizes = %d and %d, want 5 and 5", len(first), len(last))
	}
	unicode, err := p.GlobalSearch(context.Background(), "global-search-pages", "ÆØÅ_%", globalSearchPageSize, 0)
	if err != nil || len(unicode) == 0 {
		t.Fatalf("Unicode/literal search = %d rows, %v", len(unicode), err)
	}
	if rows := collectCategoryResults(t, p, "global-search-pages", "deepterm", SearchFiles); len(rows) != 510 {
		t.Fatalf("Files & Paths search past 500 findings returned %d rows", len(rows))
	}
	if rows := collectCategoryResults(t, p, "global-search-pages", "ÆØÅ_%", SearchFiles); len(rows) != 510 {
		t.Fatalf("Files & Paths literal Unicode search returned %d rows", len(rows))
	}
	if rows := collectCategoryResults(t, p, "global-search-pages", "ÆØÅ_X", SearchFiles); len(rows) != 0 {
		t.Fatalf("Files & Paths treated literal %% or _ as a wildcard: %d rows", len(rows))
	}
}

func TestGlobalSearchConcurrentReadersCancellationAndRepeatedQueries(t *testing.T) {
	path := makeFixtureDB(t, "global-search-concurrent")
	p, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	const workers = 8
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rows, err := p.GlobalSearch(context.Background(), "global-search-concurrent", "synthetic", globalSearchPageSize, 0)
			if err != nil {
				errCh <- err
				return
			}
			if len(rows) == 0 {
				errCh <- fmt.Errorf("concurrent query lost fixture match")
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.GlobalSearch(ctx, "global-search-concurrent", "synthetic", globalSearchPageSize, 0); err == nil {
		t.Fatal("canceled database search unexpectedly succeeded")
	}
	for i := 0; i < 10; i++ {
		if _, err := p.GlobalSearch(context.Background(), "global-search-concurrent", "SyntheticPassword", globalSearchPageSize, 0); err != nil {
			t.Fatalf("search cycle %d: %v", i, err)
		}
	}
}

func TestGlobalSearchCancelsActiveSQLiteScan(t *testing.T) {
	path := makeFixtureDB(t, "global-search-active-cancel")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO findings(scan_id,fingerprint,payload,path,rule_id,category,host,share) VALUES(?,?,?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50000; i++ {
		pathValue := fmt.Sprintf("/cancel-scan/%06d.cfg", i)
		payload := fmt.Sprintf(`{"rule_id":"fixture.rule","file_path":%q,"matched_text":"absent"}`, pathValue)
		if _, err := stmt.Exec("global-search-active-cancel", fmt.Sprintf("cancel-%06d", i), payload, pathValue, "fixture.rule", "test", "host", "share"); err != nil {
			t.Fatal(err)
		}
	}
	if err := stmt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := p.GlobalSearch(ctx, "global-search-active-cancel", "guaranteed-no-match", globalSearchPageSize, 0)
		done <- err
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for p.db.Stats().InUse == 0 {
		select {
		case err := <-done:
			cancel()
			if err != nil {
				t.Fatalf("search ended before becoming cancellable: %v", err)
			}
			t.Fatal("fixture query completed before cancellation could be issued")
		case <-deadline.C:
			cancel()
			t.Fatal("global search never acquired its SQLite connection")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("active search was not interrupted by context cancellation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("active SQLite search did not stop after context cancellation")
	}
	categoryCtx, cancelCategory := context.WithCancel(context.Background())
	categoryDone := make(chan error, 1)
	go func() {
		_, _, _, _, err := p.GlobalSearchCategoryPage(categoryCtx, "global-search-active-cancel", "guaranteed-no-match", SearchContent, 0, 0, globalSearchPageSize)
		categoryDone <- err
	}()
	categoryDeadline := time.NewTimer(5 * time.Second)
	defer categoryDeadline.Stop()
	for p.db.Stats().InUse == 0 {
		select {
		case err := <-categoryDone:
			cancelCategory()
			t.Fatalf("categorized search completed before cancellation: %v", err)
		case <-categoryDeadline.C:
			cancelCategory()
			t.Fatal("categorized search never acquired its SQLite connection")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancelCategory()
	select {
	case err := <-categoryDone:
		if err == nil {
			t.Fatal("active categorized search was not interrupted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("categorized SQLite search did not stop after cancellation")
	}
}

func TestGlobalSearchUsesAuthoritativeCredentialValueAndPayload(t *testing.T) {
	path := makeFixtureDB(t, "global-search-authoritative")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	secret := `Secret%_"'\\!æøå.,:;@#$^&*()+[]{}=|?/`
	if _, err := db.Exec(`INSERT INTO credentials(scan_id,credential_key,credential_type,identity,value,payload) VALUES(?,?,?,?,?,?)`, "global-search-authoritative", "password|fixture-user|evidence.txt|persisted", "password", "fixture-user", secret, `{"additional_evidence":"PayloadNeedle-ø"}`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	byValue, err := p.GlobalSearch(context.Background(), "global-search-authoritative", `%_"'\\!æøå`, globalSearchPageSize, 0)
	if err != nil {
		t.Fatal(err)
	}
	var credential *GlobalSearchResult
	for i := range byValue {
		if byValue[i].Kind == "credential" && byValue[i].Field == "credential value" {
			credential = &byValue[i]
			break
		}
	}
	if credential == nil {
		t.Fatal("authoritative credentials.value did not match")
	}
	if !strings.Contains(credential.Value, secret) || !strings.Contains(credential.Value, "evidence.txt") {
		t.Fatal("result did not preserve the full credential value and source association")
	}
	byPayload, err := p.GlobalSearch(context.Background(), "global-search-authoritative", "PayloadNeedle-Ø", globalSearchPageSize, 0)
	if err != nil || len(byPayload) == 0 {
		t.Fatalf("credential payload search = %d results, %v", len(byPayload), err)
	}
	user, err := p.GlobalSearch(context.Background(), "global-search-authoritative", "FIXTURE-USER", globalSearchPageSize, 0)
	if err != nil || len(user) == 0 {
		t.Fatalf("username search = %d results, %v", len(user), err)
	}
}

func TestGlobalSearchFirstPagePrioritizesVisibleCredentialOverAccessMatches(t *testing.T) {
	path := makeFixtureDB(t, "global-search-priority")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	largeKey := strings.Repeat("long-credential-key-", 1000)
	if _, err := db.Exec(`UPDATE credentials SET credential_key=?,value='priority-needle',payload='{"CredentialType":"password","Identity":"synthetic-user","Path":"fixture/evidence.txt","value":"priority-needle"}' WHERE scan_id=?`, largeKey, "global-search-priority"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE findings SET payload=replace(payload,'synthetic-value','priority-needle') WHERE scan_id=?`, "global-search-priority"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 75; i++ {
		if _, err := db.Exec(`INSERT INTO access_observations(scan_id,context_id,file_key,first_seen,last_seen,access_result) VALUES(?,?,?,?,?,?)`, "global-search-priority", "priority-needle", fmt.Sprintf("file-%03d", i), "now", "now", "read"); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	page, nextPhase, nextOffset, done, err := p.GlobalSearchPage(context.Background(), "global-search-priority", "priority-needle", 0, 0, globalSearchPageSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].Kind != "credential" || page[0].Field != "credential value" || done || nextPhase != 1 || nextOffset != 0 {
		t.Fatalf("first page did not expose the credential before access observations: kind=%q count=%d cursor=%d/%d done=%v", firstKind(page), len(page), nextPhase, nextOffset, done)
	}
	if page[0].Context != "fixture/evidence.txt" || !strings.Contains(page[0].Value, largeKey) {
		t.Fatal("credential result lost source path or full persisted credential key")
	}
	next, _, _, _, err := p.GlobalSearchPage(context.Background(), "global-search-priority", "priority-needle", nextPhase, nextOffset, globalSearchPageSize)
	if err != nil || len(next) != 1 || next[0].Kind != "finding" {
		t.Fatalf("second page did not retain the associated finding: kind=%q count=%d err=%v", firstKind(next), len(next), err)
	}
}

func firstKind(rows []GlobalSearchResult) string {
	if len(rows) == 0 {
		return ""
	}
	return rows[0].Kind
}

func collectCategoryResults(t *testing.T, p *Provider, scanID, query string, category GlobalSearchCategory) []GlobalSearchResult {
	t.Helper()
	var all []GlobalSearchResult
	phase, offset := 0, 0
	for pages := 0; pages < 1000; pages++ {
		rows, nextPhase, nextOffset, done, err := p.GlobalSearchCategoryPage(context.Background(), scanID, query, category, phase, offset, globalSearchPageSize)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, rows...)
		if done {
			return all
		}
		phase, offset = nextPhase, nextOffset
	}
	t.Fatal("category pagination did not finish")
	return nil
}

func categoryContains(rows []GlobalSearchResult, kind, id string) bool {
	for _, row := range rows {
		if row.Kind == kind && row.ID == id {
			return true
		}
	}
	return false
}

func TestGlobalSearchCategoriesUsePersistedMatchLocation(t *testing.T) {
	const scanID = "global-search-categories"
	path := makeFixtureDB(t, scanID)
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"rule_id":"cisco.rule","category":"credentials","file_path":"/configs/cisco/router.cfg","host":"cisco-switch01","matched_text":"username=ciscoadmin password=Cisco123","snippet":"cfgneedle configuration"}`
	if _, err := db.Exec(`UPDATE findings SET payload=?,path='/configs/cisco/router.cfg',host='cisco-switch01',rule_id='cisco.rule',category='credentials' WHERE scan_id=?`, payload, scanID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE credentials SET identity='ciscoadmin',value='Cisco123',payload='{"Identity":"ciscoadmin","Path":"/configs/cisco/router.cfg","Host":"cisco-switch01","value":"Cisco123"}' WHERE scan_id=?`, scanID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO files(scan_id,file_key,host,share,path,size,updated_at,status,semantics) VALUES(?,?,?,?,?,?,?,?,?)`, scanID, "fixture-file", "cisco-switch01", "configs", "/configs/cisco/router.cfg", 1, "now", "seen", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO shares(scan_id,host,share,status,updated_at) VALUES(?,?,?,?,?)`, scanID, "cisco-switch01", "cisco-share", "seen", "now"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO correlations(scan_id,correlation_key,payload) VALUES(?,?,?)`, scanID, "correlation-fixture", `{"type":"reuse","identity":"corruser","sources":[{"path":"/corrcfg/router.cfg","host":"corrhost","share":"corrshare"}]}`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	all := collectCategoryResults(t, p, scanID, "cisco", SearchAll)
	for _, kind := range []string{"credential", "finding", "file", "share"} {
		found := false
		for _, row := range all {
			found = found || row.Kind == kind
		}
		if !found {
			t.Fatalf("All omitted persisted %s match", kind)
		}
	}
	for _, row := range all {
		if row.Kind == "finding" && row.Field != "source path" {
			t.Fatalf("All did not identify the persisted finding field: %q", row.Field)
		}
	}
	allContent := collectCategoryResults(t, p, scanID, "cfgneedle", SearchAll)
	if len(allContent) == 0 || allContent[0].Field != "snippet" {
		t.Fatalf("All did not identify the persisted content field: %q", firstField(allContent))
	}
	var findingID, credentialID string
	for _, row := range all {
		if row.Kind == "finding" {
			findingID = row.ID
		}
		if row.Kind == "credential" {
			credentialID = row.ID
		}
	}
	for _, category := range []GlobalSearchCategory{SearchFiles, SearchContent, SearchHosts, SearchOther} {
		if !categoryContains(collectCategoryResults(t, p, scanID, "cisco", category), "finding", findingID) {
			t.Fatalf("finding did not appear in %s for its independent matching field", category)
		}
	}
	if categoryContains(collectCategoryResults(t, p, scanID, "cisco", SearchCreds), "finding", findingID) {
		t.Fatal("finding classification or embedded password incorrectly created a credential match")
	}
	for _, query := range []string{"ciscoadmin", "Cisco123"} {
		if !categoryContains(collectCategoryResults(t, p, scanID, query, SearchCreds), "credential", credentialID) {
			t.Fatalf("Credentials omitted username or authoritative value for %q", query)
		}
	}
	for _, check := range []struct {
		query    string
		category GlobalSearchCategory
		kind     string
		field    string
	}{
		{"router.cfg", SearchFiles, "finding", "source path"},
		{"cfgneedle", SearchContent, "finding", "evidence snippet"},
		{"cisco-switch01", SearchHosts, "finding", "hostname"},
		{"cisco.rule", SearchOther, "finding", "rule ID"},
	} {
		rows := collectCategoryResults(t, p, scanID, check.query, check.category)
		if !categoryContains(rows, check.kind, findingID) {
			t.Fatalf("%s omitted %s match in %s", check.category, check.query, check.kind)
		}
		for _, row := range rows {
			if row.Kind == check.kind && row.ID == findingID && row.Field != check.field {
				t.Fatalf("%s labeled %s match as %q, want %q", check.category, check.query, row.Field, check.field)
			}
		}
	}
	credentials := collectCategoryResults(t, p, scanID, "Cisco123", SearchCreds)
	if len(credentials) == 0 || credentials[0].Field != "credential value" || !strings.Contains(credentials[0].Value, "Cisco123") {
		t.Fatal("credential result lost the exact matched field or recovered value")
	}
	for _, check := range []struct {
		query    string
		category GlobalSearchCategory
	}{
		{"corruser", SearchCreds},
		{"corrcfg", SearchFiles},
		{"corrhost", SearchHosts},
		{"reuse", SearchOther},
	} {
		if !categoryContains(collectCategoryResults(t, p, scanID, check.query, check.category), "correlation", "correlation-fixture") {
			t.Fatalf("correlation %s match was omitted from %s", check.query, check.category)
		}
	}
}

func firstField(rows []GlobalSearchResult) string {
	if len(rows) == 0 {
		return ""
	}
	return rows[0].Field
}

func TestGlobalSearchCategoryPaginationIsIndependent(t *testing.T) {
	const scanID = "global-search-category-pages"
	path := makeFixtureDB(t, scanID)
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 17; i++ {
		name := fmt.Sprintf("/manyneedle/file-%03d.cfg", i)
		if _, err := db.Exec(`INSERT INTO findings(scan_id,fingerprint,payload,path,rule_id,category) VALUES(?,?,?,?,?,?)`, scanID, fmt.Sprintf("many-%03d", i), fmt.Sprintf(`{"file_path":%q,"matched_text":"contentneedle"}`, name), name, "fixture.rule", "test"); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	files := collectCategoryResults(t, p, scanID, "manyneedle", SearchFiles)
	if len(files) != 17 || len(collectCategoryResults(t, p, scanID, "manyneedle", SearchContent)) != 0 {
		t.Fatalf("category pages mixed path/content matches: files=%d", len(files))
	}
	first, phase, offset, done, err := p.GlobalSearchCategoryPage(context.Background(), scanID, "manyneedle", SearchFiles, 0, 0, globalSearchPageSize)
	if err != nil || len(first) != globalSearchPageSize || done {
		t.Fatalf("first category page = %d rows, done=%v, err=%v", len(first), done, err)
	}
	second, _, _, _, err := p.GlobalSearchCategoryPage(context.Background(), scanID, "manyneedle", SearchFiles, phase, offset, globalSearchPageSize)
	if err != nil || len(second) != globalSearchPageSize || first[0].ID == second[0].ID {
		t.Fatal("category pagination repeated or lost its cursor")
	}
}

func TestOpenRejectsMissingWithoutCreating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	if _, err := Open(path); err == nil {
		t.Fatal("expected missing database error")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("viewer created or changed missing database: %v", err)
	}
}

func TestProviderListsScansAndFindingsReadOnly(t *testing.T) {
	path := makeFixtureDB(t, "scan-one", "scan-two")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	scans, err := provider.ListScans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 2 || scans[0].FindingCount != 1 {
		t.Fatalf("unexpected scans: %#v", scans)
	}
	if scans[0].DisplayID != "scan-local-002" || scans[0].ID != "scan-two" {
		t.Fatalf("unexpected scan identifiers: %#v", scans[0])
	}
	items, err := provider.Findings(context.Background(), scans[0].ID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Finding.MatchedText != "synthetic-value" {
		t.Fatalf("unexpected findings: %#v", items)
	}
	credentials, err := provider.Credentials(context.Background(), scans[0].ID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 || credentials[0].Candidate.Value != "SyntheticPassword!" {
		t.Fatalf("unexpected credential projection: %#v", credentials)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("read-only provider changed the database file")
	}
}

func TestProviderIncludesCompletedDerivedFindingsWithStableIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "derived.db")
	state, err := store.Open(path, store.Options{ScanID: "derived-scan", SnablrVersion: "test", Semantics: "test", BatchSize: 1, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	original := scanner.Finding{RuleID: "original.rule", FilePath: "original.txt", MatchedText: "original"}
	derived := scanner.Finding{RuleID: "correlation.rule", FilePath: "derived.txt", MatchedText: "derived"}
	if err := state.RecordFinding(original); err != nil {
		t.Fatal(err)
	}
	if err := state.ResetCorrelationState(); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordDerivedFinding("family/group", derived); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := state.CompleteCorrelationState(); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	counts, err := provider.Counts(context.Background(), "derived-scan")
	if err != nil {
		t.Fatal(err)
	}
	if counts.Findings != 2 {
		t.Fatalf("finding count=%d, want 2", counts.Findings)
	}
	page, err := provider.FindingsAfter(context.Background(), "derived-scan", 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].Derived {
		t.Fatalf("unexpected original page: %#v", page)
	}
	next, err := provider.FindingsAfter(context.Background(), "derived-scan", page[0].ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(next) != 1 || !next[0].Derived || next[0].Finding.RuleID != derived.RuleID {
		t.Fatalf("unexpected derived page: %#v", next)
	}
	if next[0].ID == page[0].ID || next[0].StableID() == fmt.Sprintf("finding:%d", next[0].ID) {
		t.Fatalf("derived identity collided: %#v", next[0])
	}
	rehydrated, err := provider.Finding(context.Background(), "derived-scan", next[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if rehydrated.Finding.MatchedText != derived.MatchedText || !rehydrated.Derived {
		t.Fatalf("rehydrated derived finding: %#v", rehydrated)
	}
	search, err := provider.SearchPage(context.Background(), "derived-scan", "correlation.rule", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(search.Findings) != 1 || !search.Findings[0].Derived {
		t.Fatalf("derived search result: %#v", search.Findings)
	}
}

func TestProviderHidesDerivedFindingsDuringRebuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "building.db")
	state, err := store.Open(path, store.Options{ScanID: "building-scan", SnablrVersion: "test", Semantics: "test", BatchSize: 1, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.ResetCorrelationState(); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordDerivedFinding("incomplete", scanner.Finding{RuleID: "derived.rule"}); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	counts, err := provider.Counts(context.Background(), "building-scan")
	if err != nil {
		t.Fatal(err)
	}
	if counts.Findings != 0 {
		t.Fatalf("incomplete derived rows visible: %#v", counts)
	}
	items, err := provider.Findings(context.Background(), "building-scan", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("incomplete derived page visible: %#v", items)
	}
}

func TestProviderRehydratesDatabaseLocationFindingForFinder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database-location.db")
	state, err := store.Open(path, store.Options{ScanID: "p4-scan", SnablrVersion: "test", Semantics: "p4", QueueSize: 8, BatchSize: 1, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	want := scanner.Finding{
		RuleID:            "dbinspect.artifact.sqlite_structural",
		RuleName:          "Structurally Validated SQLite Database Artifact",
		Category:          "database-artifacts",
		SignalType:        "validated",
		Confidence:        "medium",
		TriageClass:       "weak-review",
		Host:              "fileserver",
		Share:             "data",
		FilePath:          "exports/opaque-copy",
		MatchedText:       "SQLite format 3\x00",
		Context:           "exports/opaque-copy",
		ArchivePath:       "bundle.zip",
		ArchiveMemberPath: "nested/opaque-copy",
		Tags:              []string{"database", "db:type:sqlite", "db:status:confirmed"},
	}
	if err := state.RecordFinding(want); err != nil {
		t.Fatal(err)
	}
	if err := state.SetScanStatus(store.StatusCompleted, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	items, err := provider.Findings(context.Background(), "p4-scan", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Finding.MatchedText != want.MatchedText || items[0].Finding.ArchiveMemberPath != want.ArchiveMemberPath {
		t.Fatalf("database finding did not rehydrate exactly: got %#v", items)
	}
	categories := buildCategories(nil, items, nil)
	if len(categories) != 1 || categories[0].Name != "Database Locations & Connections" {
		t.Fatalf("database finding did not survive Finder projection: %#v", categories)
	}
}

func TestProviderRehydratesStructuredDatabaseConfigurationEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "structured-database.db")
	state, err := store.Open(path, store.Options{ScanID: "p4-config", SnablrVersion: "test", Semantics: "p4", QueueSize: 8, BatchSize: 1, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	want := scanner.Finding{
		RuleID: "dbinspect.infrastructure.structured_config", RuleName: "Validated Database Configuration Endpoint",
		Category: "database-infrastructure", SignalType: "validated", Confidence: "high", TriageClass: "confirmed",
		Host: "fileserver", Share: "configs", FilePath: "opaque-config", MatchedText: `{"database":{"host":"db.example.test","port":5432,"name":"payroll"}}`,
		Snippet: `{"database":{"host":"db.example.test","port":5432,"name":"payroll"}}`, Context: `{"database":{"host":"db.example.test","port":5432,"name":"payroll"}}`,
		Tags: []string{"database", "db:source:config", "db:type:configured-endpoint", "db:status:configured"},
	}
	if err := state.RecordFinding(want); err != nil {
		t.Fatal(err)
	}
	if err := state.SetScanStatus(store.StatusCompleted, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	items, err := provider.Findings(context.Background(), "p4-config", 0, 10)
	if err != nil {
		_ = provider.Close()
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Finding.MatchedText != want.MatchedText || items[0].Finding.Snippet != want.Snippet || items[0].Finding.Context != want.Context {
		t.Fatalf("structured configuration evidence did not rehydrate exactly: got %#v", items)
	}
	categories := buildCategories(nil, items, nil)
	if len(categories) != 1 || len(categories[0].Discoveries) != 1 || categories[0].Discoveries[0].Subcategory != "Database Servers & Instances" {
		t.Fatalf("structured configuration did not survive Finder projection: %#v", categories)
	}
}

func TestProviderRehydratesDistinctDatabaseObservationsWithExactEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "distinct-database-observations.db")
	state, err := store.Open(path, store.Options{ScanID: "p4-distinct", SnablrVersion: "test", Semantics: "p4", QueueSize: 8, BatchSize: 1, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	wants := []scanner.Finding{
		{RuleID: "dbinspect.infrastructure.structured_config", RuleName: "Configured endpoint", Category: "database-infrastructure", SignalType: "validated", Confidence: "high", TriageClass: "confirmed", Host: "fileserver", Share: "configs", FilePath: "app.json", MatchedText: "host=prod;database=app", Context: "production", ObservationID: "structured:0:prod"},
		{RuleID: "dbinspect.infrastructure.structured_config", RuleName: "Configured endpoint", Category: "database-infrastructure", SignalType: "validated", Confidence: "high", TriageClass: "confirmed", Host: "fileserver", Share: "configs", FilePath: "app.json", MatchedText: "host=report;database=reporting", Context: "reporting", ObservationID: "structured:1:report"},
	}
	for _, want := range wants {
		if err := state.RecordFinding(want); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	items, err := provider.Findings(context.Background(), "p4-distinct", 0, 10)
	if err != nil {
		_ = provider.Close()
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if len(items) != len(wants) {
		t.Fatalf("distinct observations were not persisted: got %d items: %#v", len(items), items)
	}
	for index, want := range wants {
		got := items[index].Finding
		if got.ObservationID != want.ObservationID || got.MatchedText != want.MatchedText || got.Context != want.Context {
			t.Fatalf("observation %d changed during persistence: got %#v want %#v", index, got, want)
		}
	}
	categories := buildCategories(nil, items, nil)
	if len(categories) != 1 || len(categories[0].Discoveries) != 2 {
		t.Fatalf("Finder lost distinct database observations: %#v", categories)
	}
}

func TestProviderFallsBackToLegacyScanIDWhenNoDisplayLabelExists(t *testing.T) {
	path := makeFixtureDB(t, "legacy-scan")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM scan_labels WHERE scan_id=?`, "legacy-scan"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	scans, err := provider.ListScans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 1 || scans[0].ID != "legacy-scan" || scans[0].DisplayID != "legacy-scan" {
		t.Fatalf("unexpected legacy scan identifiers: %#v", scans)
	}
}

func TestProviderBoundsFindingPage(t *testing.T) {
	path := makeFixtureDB(t, "scan-one")
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	if _, err := provider.Findings(context.Background(), "scan-one", -1, 1); err == nil {
		t.Fatal("expected negative offset error")
	}
	if _, err := provider.Findings(context.Background(), "scan-one", 0, PageSize+1); err == nil {
		t.Fatal("expected page size error")
	}
}

func TestProviderPreservesP3CaptureValuesAndTypes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p3-captures.db")
	values := []credentialanalysis.Candidate{
		{CredentialType: "kerberos_asrep", Identity: "alice", Domain: "SYNTHETIC", Value: "$krb5asrep$23$alice@SYNTHETIC:00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff", Verification: credentialanalysis.Confirmed, Path: "captures"},
		{CredentialType: "kerberos_tgs", Identity: "alice", Domain: "SYNTHETIC", Value: "$krb5tgs$23$*alice$SYNTHETIC$cifs/server*$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff", Verification: credentialanalysis.Confirmed, Path: "captures"},
		{CredentialType: "dcc", Identity: "alice", Value: "$DCC1#alice#00112233445566778899aabbccddeeff", Verification: credentialanalysis.Confirmed, Path: "captures"},
		{CredentialType: "dcc2", Identity: "alice", Value: "$DCC2$10240#alice#00112233445566778899aabbccddeeff", Verification: credentialanalysis.Confirmed, Path: "archive.zip!captures"},
	}
	state, err := store.Open(path, store.Options{ScanID: "p3-scan", SnablrVersion: "test", Semantics: "p3", QueueSize: 8, BatchSize: 1, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range values {
		if err := state.RecordCredential(candidate); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	got, err := provider.Credentials(context.Background(), "p3-scan", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(values) {
		t.Fatalf("credential count = %d, want %d", len(got), len(values))
	}
	for index, expected := range values {
		if got[index].Candidate.CredentialType != expected.CredentialType || got[index].Candidate.Value != expected.Value || got[index].Candidate.Path != expected.Path {
			t.Fatalf("credential %d = %#v, want %#v", index, got[index].Candidate, expected)
		}
	}
}

func TestProviderCountsAndBoundedSearchPage(t *testing.T) {
	path := makeFixtureDB(t, "scan-search")
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	counts, err := provider.Counts(context.Background(), "scan-search")
	if err != nil {
		t.Fatal(err)
	}
	if counts.Findings != 1 || counts.Credentials != 1 || counts.Correlations != 0 {
		t.Fatalf("unexpected persisted counts: %#v", counts)
	}
	page, err := provider.SearchPage(context.Background(), "scan-search", "synthetic", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Findings) != 1 || len(page.Credentials) != 1 || page.PersistedRows != 2 {
		t.Fatalf("unexpected bounded search page: %#v", page)
	}
	if _, err := provider.SearchPage(context.Background(), "scan-search", "synthetic", PageSize+1); err == nil {
		t.Fatal("expected bounded search page validation")
	}
}

func TestProviderSearchPageAfterTraversesEveryPopulationWithoutDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "search-pages.db")
	state, err := store.Open(path, store.Options{ScanID: "scan-pages", SnablrVersion: "test", Semantics: "synthetic", QueueSize: 32, BatchSize: 32, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	const total = PageSize + 17
	for index := 0; index < total; index++ {
		if err := state.RecordFinding(scanner.Finding{RuleID: "page.rule", RuleName: "Page Search", MatchedText: fmt.Sprintf("page-token-%04d", index), FilePath: fmt.Sprintf("evidence/%04d.txt", index)}); err != nil {
			t.Fatal(err)
		}
		if err := state.RecordCredential(credentialanalysis.Candidate{CredentialType: "password", Identity: fmt.Sprintf("page-user-%04d", index), Value: fmt.Sprintf("page-token-%04d", index)}); err != nil {
			t.Fatal(err)
		}
		if err := state.RecordCorrelation(fmt.Sprintf("page-correlation-%04d", index), map[string]any{"payload": fmt.Sprintf("page-token-%04d", index)}); err != nil {
			t.Fatal(err)
		}
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
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	seen := make(map[string]struct{}, total*3)
	var findingCursor, credentialCursor int64
	var correlationCursor string
	for pageNumber := 0; ; pageNumber++ {
		page, err := provider.SearchPageAfter(context.Background(), "scan-pages", "page-token", findingCursor, credentialCursor, correlationCursor, PageSize)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Findings {
			ref := findingRowRef(item)
			if _, exists := seen[ref]; exists {
				t.Fatalf("duplicate finding reference on page %d: %s", pageNumber, ref)
			}
			seen[ref] = struct{}{}
		}
		for _, item := range page.Credentials {
			ref := credentialRowRef(item)
			if _, exists := seen[ref]; exists {
				t.Fatalf("duplicate credential reference on page %d: %s", pageNumber, ref)
			}
			seen[ref] = struct{}{}
		}
		for _, item := range page.Correlations {
			ref := correlationRowRef(item)
			if _, exists := seen[ref]; exists {
				t.Fatalf("duplicate correlation reference on page %d: %s", pageNumber, ref)
			}
			seen[ref] = struct{}{}
		}
		if len(page.Findings) > 0 {
			findingCursor = page.FindingCursor
		}
		if len(page.Credentials) > 0 {
			credentialCursor = page.CredentialCursor
		}
		if len(page.Correlations) > 0 {
			correlationCursor = page.CorrelationCursor
		}
		if page.Done {
			break
		}
		if page.PersistedRows == 0 {
			t.Fatal("search continuation made no progress")
		}
	}
	if want := total * 3; len(seen) != want {
		t.Fatalf("search references = %d, want %d", len(seen), want)
	}
}

func TestCredentialGroupExpansionIsIndependentOfPageBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential-groups.db")
	state, err := store.Open(path, store.Options{ScanID: "scan-groups", SnablrVersion: "test", Semantics: "synthetic", QueueSize: 32, BatchSize: 32, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	const total = PageSize + 9
	for index := 0; index < total; index++ {
		if err := state.RecordCredential(credentialanalysis.Candidate{CredentialType: "password", Identity: "shared-user", Value: "shared-value", Path: fmt.Sprintf("group/%04d.ini", index), Host: "HOST", Share: "Share"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.RecordCredential(credentialanalysis.Candidate{CredentialType: "password", Identity: "unrelated-user", Value: "shared-value", Path: "unrelated.ini"}); err != nil {
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
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	first, err := provider.CredentialsAfter(context.Background(), "scan-groups", 0, PageSize)
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.CredentialsAfter(context.Background(), "scan-groups", first[len(first)-1].ID, PageSize)
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := expandCredentialGroups(context.Background(), provider, "scan-groups", first)
	if err != nil {
		t.Fatal(err)
	}
	categories, _ := buildCategoriesWithAccounting("scan-groups", expanded, nil, nil)
	if len(categories) != 1 || len(categories[0].Discoveries) != 1 || len(categories[0].Discoveries[0].PersistedRefs) != PageSize {
		t.Fatalf("first page group projection = categories=%d discoveries=%d refs=%d", len(categories), len(categories[0].Discoveries), len(categories[0].Discoveries[0].PersistedRefs))
	}
	expandedSecond, err := expandCredentialGroups(context.Background(), provider, "scan-groups", second)
	if err != nil {
		t.Fatal(err)
	}
	canonicalSecond := retainCanonicalCredentialGroups(expandedSecond, second)
	secondCategories, _ := buildCategoriesWithAccounting("scan-groups", canonicalSecond, nil, nil)
	if len(secondCategories) != 1 || len(secondCategories[0].Discoveries) != 1 {
		t.Fatalf("second page should retain only unrelated canonical group: %#v", secondCategories)
	}
	if got := len(secondCategories[0].Discoveries[0].PersistedRefs); got != 1 {
		t.Fatalf("unrelated second-page group refs=%d, want 1", got)
	}
	matchedOnly, err := provider.SearchPage(context.Background(), "scan-groups", "group/0508.ini", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(matchedOnly.Credentials) != 1 {
		t.Fatalf("search matched credentials=%d, want 1", len(matchedOnly.Credentials))
	}
	matchedExpanded, err := expandCredentialGroups(context.Background(), provider, "scan-groups", matchedOnly.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	matchedCategories, _ := buildCategoriesWithAccounting("scan-groups", matchedExpanded, nil, nil)
	if len(matchedCategories) != 1 || len(matchedCategories[0].Discoveries) != 1 || len(matchedCategories[0].Discoveries[0].PersistedRefs) < PageSize {
		t.Fatalf("search relationship context lost: categories=%d discoveries=%d refs=%d", len(matchedCategories), len(matchedCategories[0].Discoveries), len(matchedCategories[0].Discoveries[0].PersistedRefs))
	}
}

func TestCredentialRelationshipPagesTraverseTenThousandRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large-credential-group.db")
	state, err := store.Open(path, store.Options{ScanID: "scan-large-group", SnablrVersion: "test", Semantics: "synthetic", QueueSize: 8, BatchSize: 1, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	const total = 10000
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < total; index++ {
		candidate := credentialanalysis.Candidate{CredentialType: "password", Identity: "large-user", Value: "large-value", Path: fmt.Sprintf("large/%05d.ini", index)}
		payload, err := json.Marshal(candidate)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		var payloadObject map[string]any
		if err := json.Unmarshal(payload, &payloadObject); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		payloadObject["value"] = candidate.Value
		payload, err = json.Marshal(payloadObject)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if _, err := tx.Exec("INSERT INTO credentials(scan_id,credential_key,credential_type,identity,value,payload) VALUES(?,?,?,?,?,?)", "scan-large-group", fmt.Sprintf("password|large-user|%s|large-value", candidate.Path), candidate.CredentialType, candidate.Identity, candidate.Value, payload); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	seed, err := provider.CredentialsAfter(context.Background(), "scan-large-group", 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 1 {
		t.Fatal("missing large-group seed")
	}
	if seed[0].Candidate.CredentialType != "password" || seed[0].Candidate.Identity != "large-user" || seed[0].Candidate.Value != "large-value" {
		t.Fatalf("unexpected seed candidate: %#v", seed[0].Candidate)
	}
	seen := map[string]struct{}{}
	after := int64(0)
	for {
		page, err := provider.RelatedCredentialsAfter(context.Background(), "scan-large-group", seed[0], after, PageSize)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page {
			ref := credentialRowRef(item)
			if _, duplicate := seen[ref]; duplicate {
				t.Fatalf("duplicate related reference %s", ref)
			}
			seen[ref] = struct{}{}
			after = item.ID
		}
		if len(page) < PageSize {
			break
		}
	}
	if len(seen) != total {
		t.Fatalf("related references=%d, want %d", len(seen), total)
	}
}
