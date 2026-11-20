package credentialanalysis

import "testing"

// Command-line scripts declare their switch letters as constants
// (SHORTCUT_USERNAME = "u", SHORTCUT_PASSWORD = "p"). A one- or two-letter
// value is never confirmed as a password; it stays review material.
func TestShortValuesAreNeverConfirmed(t *testing.T) {
	script := "private const SHORTCUT_FORMAT      = \"f\"\r\n" +
		"private const SHORTCUT_PASSWORD    = \"p\"\r\n" +
		"private const SHORTCUT_REMOTE      = \"r\"\r\n" +
		"private const SHORTCUT_USERNAME    = \"u\"\r\n"
	candidates := Harvest(HarvestInput{Path: "Windows/System32/remotetool.vbs", Content: []byte(script)})
	review := false
	for _, c := range candidates {
		if c.Verification == Confirmed {
			t.Errorf("switch constant confirmed as a credential: %+v", c)
		}
		if c.Value == "p" {
			review = true
		}
	}
	if !review {
		t.Errorf("short value not kept for review: %+v", candidates)
	}

	// A real pair in the same shape is still confirmed.
	config := "DEPLOY_USERNAME = \"svc_deploy\"\nDEPLOY_PASSWORD = \"Tr4in-Depot-61\"\n"
	confirmed := false
	for _, c := range Harvest(HarvestInput{Path: "scripts/deploy.env", Content: []byte(config)}) {
		if c.Verification == Confirmed && c.Value == "Tr4in-Depot-61" {
			confirmed = true
		}
	}
	if !confirmed {
		t.Error("real environment pair no longer confirmed")
	}
}

// An all-capitals underscore value is a template ("DB_PASSWORD") when it is
// built from credential or template words. Without those words it can be a
// real password ("BLUE_HARBOR_LANTERN"): it is kept, but only for review.
func TestConstantShapedValuesAreKeptForReview(t *testing.T) {
	config := "[OPTIONS]\nSQLSVCACCOUNT=\"CORP\\sqlsvc\"\nSQLSVCPASSWORD=\"BLUE_HARBOR_LANTERN\"\n"
	var found *Candidate
	for _, c := range Harvest(HarvestInput{Path: "setup/sql/ConfigurationFile.ini", Content: []byte(config)}) {
		if c.Value == "BLUE_HARBOR_LANTERN" {
			c := c
			found = &c
		}
	}
	if found == nil {
		t.Fatal("constant-shaped password dropped")
	}
	if found.Verification != Review {
		t.Errorf("constant-shaped password is %s, want review", found.Verification)
	}
	for _, value := range []string{"DB_PASSWORD", "SERVICE_ACCOUNT_NAME", "API_KEY", "ADMIN_USER", "YOUR_SECRET_HERE"} {
		if !IsPlaceholderValue(value) {
			t.Errorf("%q no longer a placeholder", value)
		}
	}
}
