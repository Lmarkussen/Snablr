package credentialanalysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func deploymentFixture(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "deployment-credential-regression", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return content
}

func TestHarvestWindowsDeploymentCredentials(t *testing.T) {
	tests := []struct {
		name       string
		fixture    string
		value      string
		identity   string
		domain     string
		conf       Verification
		wantReview bool
	}{
		{
			name:       "CustomSettings AdminPassword",
			fixture:    "CustomSettings.ini",
			value:      "LafDm-Deployment-Test-001!",
			identity:   "Administrator",
			domain:     "CONTOSO",
			conf:       Confirmed,
			wantReview: true,
		},
		{
			name:     "Bootstrap UserPassword",
			fixture:  "Bootstrap.ini",
			value:    "Bootstrap-Test-005!",
			identity: "deployuser",
			domain:   "CONTOSO",
			conf:     Confirmed,
		},
		{
			name:       "unattend AdministratorPassword",
			fixture:    "unattend.xml",
			value:      "Unattend-Admin-Test-002!",
			identity:   "Administrator",
			conf:       Confirmed,
			wantReview: true,
		},
		{
			name:       "unattend AutoLogon password",
			fixture:    "unattend.xml",
			value:      "AutoLogon-Test-003!",
			identity:   "Administrator",
			domain:     "CONTOSO",
			conf:       Confirmed,
			wantReview: true,
		},
		{
			name:       "unattend Credentials password",
			fixture:    "unattend.xml",
			value:      "Deploy-Test-004!",
			identity:   "deploysvc",
			domain:     "CONTOSO",
			conf:       Confirmed,
			wantReview: true,
		},
		{
			name:       "misleading .xlm extension",
			fixture:    "unattned.xlm",
			value:      "Misleading-Extension-Test-006!",
			identity:   "Administrator",
			conf:       Confirmed,
			wantReview: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := test.fixture
			if test.fixture == "unattned.xlm" {
				path = "unattned.xlm"
			}
			candidates := Harvest(HarvestInput{Content: deploymentFixture(t, test.fixture), Path: path})
			found := false
			for _, candidate := range candidates {
				if candidate.Value != test.value {
					continue
				}
				found = true
				if test.conf != "" && candidate.Verification != test.conf {
					t.Errorf("verification = %q, want %q", candidate.Verification, test.conf)
				}
				if test.identity != "" && candidate.Identity != test.identity {
					t.Errorf("identity = %q, want %q", candidate.Identity, test.identity)
				}
				if test.domain != "" && candidate.Domain != test.domain {
					t.Errorf("domain = %q, want %q", candidate.Domain, test.domain)
				}
				if test.wantReview && candidate.Verification != Review && !strings.Contains(candidate.ValidationBasis, "structured") && !strings.Contains(candidate.ValidationBasis, "windows") {
					t.Logf("candidate %#v", candidate)
				}
			}
			if !found {
				t.Fatalf("value %q was not harvested; got %#v", test.value, candidates)
			}
		})
	}
}

func TestHarvestCompoundPasswordFieldSemantics(t *testing.T) {
	var candidates []Candidate
	for _, fixture := range []string{
		"compound-password-fields.ini",
		"compound-sql-snake.ini",
		"compound-db-hyphen.ini",
		"compound-user-dot.ini",
		"compound-app-camel.ini",
	} {
		candidates = append(candidates, Harvest(HarvestInput{Content: deploymentFixture(t, fixture), Path: fixture})...)
	}
	want := map[string]string{
		"Compound-Admin-Test-001!":         "password",
		"Compound-Administrator-Test-002!": "password",
		"Compound-DomainAdmin-Test-003!":   "password",
		"Compound-Join-Test-004!":          "password",
		"Compound-Service-Test-005!":       "password",
		"Compound-Backup-Test-006!":        "password",
		"Compound-Database-Test-007!":      "password",
		"Compound-SQL-Test-008!":           "password",
		"Compound-User-Test-009!":          "password",
		"Compound-Account-Test-010!":       "password",
		"Compound-LocalAdmin-Test-011!":    "password",
		"Compound-SQL-Snake-Test-012!":     "password",
		"Compound-DB-Hyphen-Test-013!":     "password",
		"Compound-User-Dot-Test-014!":      "password",
		"Compound-App-Camel-Test-015!":     "password",
	}
	for value, credentialType := range want {
		if !hasCredentialCandidate(candidates, value, credentialType) {
			t.Errorf("missing %s candidate for %q in %#v", credentialType, value, candidates)
		}
	}
	if len(candidates) < len(want) {
		t.Fatalf("expected at least %d candidates, got %d", len(want), len(candidates))
	}
}

func TestStandaloneAdminPasswordSurfacesForReview(t *testing.T) {
	candidates := Harvest(HarvestInput{Content: []byte("AdminPassword=Standalone-Admin-Test!\n"), Path: "standalone.ini"})
	if !hasCandidate(candidates, Review, "Standalone-Admin-Test!") {
		t.Fatalf("standalone AdminPassword was not retained for review: %#v", candidates)
	}
}

func TestUnattendPlainTextFalseIsNotConfirmedPlaintext(t *testing.T) {
	content := []byte(`<unattend xmlns="urn:schemas-microsoft-com:unattend"><AutoLogon><Password><Value>Encoded-Or-Hashed-Test!</Value><PlainText>false</PlainText></Password><Username>Administrator</Username><Domain>CONTOSO</Domain></AutoLogon></unattend>`)
	candidates := Harvest(HarvestInput{Content: content, Path: "unattend-plaintext-false.xml"})
	if !hasCandidate(candidates, Review, "Encoded-Or-Hashed-Test!") {
		t.Fatalf("PlainText=false password was not retained for review: %#v", candidates)
	}
	for _, candidate := range candidates {
		if candidate.Value == "Encoded-Or-Hashed-Test!" && candidate.Verification == Confirmed {
			t.Fatalf("PlainText=false password was incorrectly confirmed: %#v", candidate)
		}
	}
}

func TestHarvestPasswordMetadataKeysAreNotSecret(t *testing.T) {
	candidates := Harvest(HarvestInput{Content: deploymentFixture(t, "negative-password-metadata.ini"), Path: "negative-password-metadata.ini"})
	if len(candidates) != 0 {
		t.Fatalf("password metadata keys produced credential candidates: %#v", candidates)
	}
}

func TestHarvestDocumentationAndSchemaAreNotSecrets(t *testing.T) {
	docs := Harvest(HarvestInput{Content: deploymentFixture(t, "password-docs.txt"), Path: "password-docs.txt"})
	for _, candidate := range docs {
		if candidate.Value != "" {
			t.Fatalf("documentation produced a credential candidate: %#v", candidate)
		}
	}
	schema := Harvest(HarvestInput{Content: deploymentFixture(t, "password-schema.xml"), Path: "password-schema.xml"})
	for _, candidate := range schema {
		if candidate.Value != "" {
			t.Fatalf("schema documentation produced a credential candidate: %#v", candidate)
		}
	}
}

func TestDeploymentCredentialRegressionOracle(t *testing.T) {
	positive := []struct {
		fixture string
		value   string
	}{
		{"CustomSettings.ini", "LafDm-Deployment-Test-001!"},
		{"Bootstrap.ini", "Bootstrap-Test-005!"},
		{"compound-password-fields.ini", "Compound-Admin-Test-001!"},
		{"compound-password-fields.ini", "Compound-Administrator-Test-002!"},
		{"compound-password-fields.ini", "Compound-DomainAdmin-Test-003!"},
		{"compound-password-fields.ini", "Compound-Join-Test-004!"},
		{"compound-password-fields.ini", "Compound-Service-Test-005!"},
		{"compound-password-fields.ini", "Compound-Backup-Test-006!"},
		{"compound-password-fields.ini", "Compound-Database-Test-007!"},
		{"compound-password-fields.ini", "Compound-SQL-Test-008!"},
		{"compound-password-fields.ini", "Compound-User-Test-009!"},
		{"compound-password-fields.ini", "Compound-Account-Test-010!"},
		{"compound-password-fields.ini", "Compound-LocalAdmin-Test-011!"},
		{"compound-sql-snake.ini", "Compound-SQL-Snake-Test-012!"},
		{"compound-db-hyphen.ini", "Compound-DB-Hyphen-Test-013!"},
		{"compound-user-dot.ini", "Compound-User-Dot-Test-014!"},
		{"compound-app-camel.ini", "Compound-App-Camel-Test-015!"},
		{"unattend.xml", "Unattend-Admin-Test-002!"},
		{"unattend.xml", "AutoLogon-Test-003!"},
		{"unattend.xml", "Deploy-Test-004!"},
		{"unattned.xlm", "Misleading-Extension-Test-006!"},
	}

	seen := map[string]bool{}
	var candidates []Candidate
	for _, item := range positive {
		seen[item.value] = true
		candidates = append(candidates, Harvest(HarvestInput{Content: deploymentFixture(t, item.fixture), Path: item.fixture})...)
	}
	surfaced := map[string]bool{}
	for _, candidate := range candidates {
		if candidate.Value != "" {
			surfaced[candidate.Value] = true
		}
	}
	missed := 0
	for value := range seen {
		if !surfaced[value] {
			missed++
			t.Errorf("seeded credential %q was not surfaced", value)
		}
	}
	if missed != 0 {
		t.Fatalf("seeded credentials: %d, surfaced: %d, missed: %d", len(seen), len(surfaced), missed)
	}

	negative := []string{
		"negative-password-metadata.ini",
		"password-docs.txt",
		"password-schema.xml",
	}
	for _, fixture := range negative {
		if got := Harvest(HarvestInput{Content: deploymentFixture(t, fixture), Path: fixture}); len(got) != 0 {
			t.Fatalf("negative fixture %s produced false credential candidates: %#v", fixture, got)
		}
	}
}

func TestDeploymentCredentialHarvestIncrementalChangeDoesNotReuseOldValue(t *testing.T) {
	oldContent := []byte("[Default]\nAdminUser=Administrator\nAdminPassword=Old-Deployment-Test!\nAdminDomain=CONTOSO\n")
	changedContent := []byte("[Default]\nAdminUser=Administrator\nAdminPassword=New-Deployment-Test!\nAdminDomain=CONTOSO\n")

	oldCandidates := Harvest(HarvestInput{Content: oldContent, Path: "CustomSettings.ini"})
	if !hasCredentialCandidate(oldCandidates, "Old-Deployment-Test!", "password") {
		t.Fatalf("old deployment credential was not surfaced: %#v", oldCandidates)
	}
	newCandidates := Harvest(HarvestInput{Content: changedContent, Path: "CustomSettings.ini"})
	if !hasCredentialCandidate(newCandidates, "New-Deployment-Test!", "password") {
		t.Fatalf("changed deployment credential was not surfaced: %#v", newCandidates)
	}
	if hasCredentialCandidate(newCandidates, "Old-Deployment-Test!", "password") {
		t.Fatalf("old deployment credential was incorrectly reused: %#v", newCandidates)
	}
}

func hasCredentialCandidate(candidates []Candidate, value, credentialType string) bool {
	for _, candidate := range candidates {
		if candidate.Value == value && candidate.CredentialType == credentialType {
			return true
		}
	}
	return false
}
