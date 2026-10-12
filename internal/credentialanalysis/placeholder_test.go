package credentialanalysis

import "testing"

// Every value, path and host in this file is independently invented synthetic
// data. None of it is derived from customer, lab or live scan material.

func analyzeHarvest(path, content string) Report {
	return Analyze(Harvest(HarvestInput{Content: []byte(content), Path: path}))
}

func countReportCandidates(report Report) int {
	return len(report.Confirmed) + len(report.Review)
}

// TestPlaceholderMatrixIsSuppressedFromCredentialMaterial is the synthetic
// regression matrix for placeholder and template suppression. A recognised
// placeholder must never appear as confirmed material, review material or
// sensitive export material.
func TestPlaceholderMatrixIsSuppressedFromCredentialMaterial(t *testing.T) {
	t.Parallel()

	suppressed := []struct {
		name    string
		path    string
		content string
	}{
		{
			name:    "xml symbolic template pair",
			path:    "config/synthetic-directory.xml",
			content: `<?xml version="1.0"?><SyntheticDirectory><DirectoryUser>USER_TEMPLATE</DirectoryUser><DirectoryPassword>PASSWORD_TEMPLATE</DirectoryPassword></SyntheticDirectory>`,
		},
		{
			name:    "xml add template pair",
			path:    "config/synthetic-settings.xml",
			content: `<SyntheticSettings><add key="DirectoryUser" value="USER_TEMPLATE"/><add key="DirectoryPassword" value="PASSWORD_TEMPLATE"/></SyntheticSettings>`,
		},
		{
			name:    "percent wrapper",
			path:    "config/synthetic-percent.env",
			content: "Username=%APP_USER%\nPassword=%APP_PASS%\n",
		},
		{
			name:    "braced wrapper",
			path:    "config/synthetic-braced.env",
			content: "Username=${APP_USER}\nPassword=${APP_PASSWORD}\n",
		},
		{
			name:    "double brace wrapper",
			path:    "config/synthetic-handlebars.env",
			content: "Username={{SERVICE_USER}}\nPassword={{SERVICE_PASSWORD}}\n",
		},
		{
			name:    "masked value",
			path:    "config/synthetic-masked.env",
			content: "Username=synthetic-user\nPassword=********\n",
		},
		{
			name:    "empty value",
			path:    "config/synthetic-empty.env",
			content: "Username=synthetic-user\nPassword=\n",
		},
		{
			name:    "symbolic all caps pair",
			path:    "config/synthetic-symbolic.env",
			content: "APP_USER=USER_TEMPLATE\nAPP_PASSWORD=PASSWORD_TEMPLATE\n",
		},
		{
			name:    "replace me template",
			path:    "config/synthetic-replace.env",
			content: "Username=svc_synthetic\nPassword=REPLACE_ME\n",
		},
		{
			name:    "change me template",
			path:    "config/synthetic-change.env",
			content: "Username=svc_synthetic\nPassword=CHANGEME\n",
		},
	}

	for _, test := range suppressed {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if candidates := Harvest(HarvestInput{Content: []byte(test.content), Path: test.path}); len(candidates) != 0 {
				t.Fatalf("placeholder produced harvest candidates: %#v", candidates)
			}
			report := analyzeHarvest(test.path, test.content)
			if countReportCandidates(report) != 0 {
				t.Fatalf("placeholder reached credential material: confirmed=%d review=%d", len(report.Confirmed), len(report.Review))
			}
		})
	}
}

// TestAnalyzeSuppressesPlaceholdersInEverySection proves suppression happens in
// the shared classifier, so no output projection (confirmed, review, creds-out)
// can observe a placeholder.
func TestAnalyzeSuppressesPlaceholdersInEverySection(t *testing.T) {
	t.Parallel()

	report := Analyze([]Candidate{
		{Verification: Confirmed, CredentialType: "password", Identity: "%APP_USER%", Value: "%APP_PASS%", Path: "config/synthetic-percent.env", Host: "synthetic-host.test", Share: "SyntheticShare"},
		{Verification: Confirmed, CredentialType: "password", Identity: "USER_TEMPLATE", Value: "PASSWORD_TEMPLATE", Path: "config/synthetic-directory.xml"},
		{Verification: Review, CredentialType: "password", Value: "********", Path: "config/synthetic-masked.env"},
		{Verification: Review, CredentialType: "password", Value: "${APP_PASSWORD}", Path: "config/synthetic-braced.env"},
		{Verification: Confirmed, CredentialType: "connection_string", Value: "Server=SERVER_TEMPLATE;User ID=USER_TEMPLATE;Password=PASSWORD_TEMPLATE;", Path: "config/synthetic-db.env"},
	})
	if len(report.Confirmed) != 0 || len(report.Review) != 0 {
		t.Fatalf("placeholders reached credential material: confirmed=%#v review=%#v", report.Confirmed, report.Review)
	}
	if report.SuppressedPlaceholders != 5 {
		t.Fatalf("suppressed placeholder count = %d, want 5", report.SuppressedPlaceholders)
	}
	if report.CandidatesAnalyzed != 5 {
		t.Fatalf("candidates analyzed = %d, want 5", report.CandidatesAnalyzed)
	}
}

// TestPlaceholderIdentityBlocksConfirmation proves a symbolic identity can never
// confirm a password on its own, while a genuine password value is still
// retained for review.
func TestPlaceholderIdentityBlocksConfirmation(t *testing.T) {
	t.Parallel()

	report := analyzeHarvest("config/synthetic-identity.env", "[SyntheticApp]\nUsername=%APP_USER%\nPassword=SyntheticReal482!\n")
	if len(report.Confirmed) != 0 {
		t.Fatalf("placeholder identity confirmed a password: %#v", report.Confirmed)
	}
	found := false
	for _, candidate := range report.Candidates {
		if candidate.Value != "SyntheticReal482!" {
			continue
		}
		found = true
		if candidate.Verification != Review {
			t.Fatalf("verification = %q, want review for a placeholder identity", candidate.Verification)
		}
	}
	if !found {
		t.Fatalf("real password was dropped along with the placeholder identity: %#v", report)
	}
}

// TestRealExplicitSecretsSurvivePlaceholderRules is the strong-secret override:
// no real explicit credential may be suppressed for being uppercase, short,
// dictionary-like, low entropy or period-terminated.
func TestRealExplicitSecretsSurvivePlaceholderRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		content string
		value   string
	}{
		{"structured config pair", "config/synthetic-app.ini", "[SyntheticApp]\nUsername=synthetic-user\nPassword=SyntheticReal482!\n", "SyntheticReal482!"},
		{"admin password trailing period", "config/synthetic-deploy.ini", "[Default]\nAdminUser=Administrator\nAdminPassword=Summer2026.\n", "Summer2026."},
		{"uppercase only secret", "config/synthetic-upper.ini", "[SyntheticApp]\nUser=synthetic-user\nPassword=ONLYUPPERCASE42\n", "ONLYUPPERCASE42"},
		{"short dictionary-like password", "config/synthetic-short.ini", "[SyntheticApp]\nUser=synthetic-user\nPwd=WeakButReal\n", "WeakButReal"},
		{"powershell service password", "scripts/synthetic-deploy.ps1", "$SvcPass = \"SyntheticService482!\"\n", "SyntheticService482!"},
		{"shell run password", "scripts/synthetic-run.sh", "export RUN_PASSWORD=SyntheticRun482!\n", "SyntheticRun482!"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidates := Harvest(HarvestInput{Content: []byte(test.content), Path: test.path})
			if candidateForValue(candidates, test.value) == nil {
				t.Fatalf("real credential %q was suppressed: %#v", test.value, candidates)
			}
			report := Analyze(candidates)
			if report.SuppressedPlaceholders != 0 {
				t.Fatalf("real credential %q was counted as a placeholder", test.value)
			}
		})
	}
}

// TestPlaceholderReasonStructuralShapes exercises the structural classifier
// directly, including the boundaries that must stay reachable.
func TestPlaceholderReasonStructuralShapes(t *testing.T) {
	t.Parallel()

	placeholders := []string{
		"%APP_USER%", "%APP_PASS%",
		"${APP_USER}", "${APP_PASSWORD}",
		"{{SERVICE_USER}}", "{{SERVICE_PASSWORD}}",
		"<PASSWORD>", "<YOUR_PASSWORD>",
		"USER_TEMPLATE", "PASSWORD_TEMPLATE", "DB_PASSWORD", "SERVICE_ACCOUNT_NAME",
		"ACCOUNT_NAME_TEMPLATE", "REPLACE_ME", "YOUR_PASSWORD", "CHANGEME",
		"PLACEHOLDER", "EXAMPLE", "SAMPLE", "********",
	}
	for _, value := range placeholders {
		if reason, ok := PlaceholderReason(value); !ok {
			t.Errorf("PlaceholderReason(%q) = false, want a placeholder (%s)", value, reason)
		}
	}

	reachable := []string{
		"SyntheticReal482!",
		"Summer2026.",
		"ONLYUPPERCASE42",
		"WeakButReal",
		"SyntheticService482!",
		"SyntheticRun482!",
		"SyntheticDB482!",
		"synthetic-user",
		"svc_synthetic",
		"Administrator",
	}
	for _, value := range reachable {
		if reason, ok := PlaceholderReason(value); ok {
			t.Errorf("PlaceholderReason(%q) rejected a real value (%s)", value, reason)
		}
	}
}

// TestPlaceholderReasonConnectionStrings covers real and placeholder database
// connection strings.
func TestPlaceholderReasonConnectionStrings(t *testing.T) {
	t.Parallel()

	real := "Server=db.synthetic.test;User ID=svc_synthetic;Password=SyntheticDB482!;"
	if reason, ok := PlaceholderReason(real); ok {
		t.Fatalf("real connection string was classified as a placeholder (%s)", reason)
	}
	placeholder := "Server=SERVER_TEMPLATE;User ID=USER_TEMPLATE;Password=PASSWORD_TEMPLATE;"
	if _, ok := PlaceholderReason(placeholder); !ok {
		t.Fatalf("placeholder connection string was not suppressed: %q", placeholder)
	}
}
