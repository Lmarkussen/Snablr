package credentialanalysis

import "testing"

// TestHarvestRejectsSQLFragmentCredentials is the required negatives oracle for
// credential value-shape validation. SQL variables, function calls, expressions,
// schema/metadata definitions and prose fragments must never become credential
// candidates just because a credential-like label precedes them.
func TestHarvestRejectsSQLFragmentCredentials(t *testing.T) {
	t.Parallel()

	negatives := []string{
		"Password=@var\n",
		"Password=@bind_value\n",
		"Password=func(column_a, 1, 2)\n",
		"Password=value and\n",
		"PASSWORD=field,,type(255)\n",
		"Password=plain words here\n",
		"Password=several plain words\n",
		"Password=stored in a vault\n",
		"\t10,,FIELD,,,FIELD,A descriptive label\n",
	}
	for _, content := range negatives {
		candidates := Harvest(HarvestInput{Content: []byte(content), Path: "install.sql"})
		if len(candidates) != 0 {
			t.Errorf("expected no credential candidate for %q, got %#v", content, candidates)
		}
	}
}

// TestHarvestPreservesGenuineScriptCredentials is the required positives oracle.
// Value-shape validation must never remove real scalar credentials, including
// short, low-entropy, explicitly written ones.
func TestHarvestPreservesGenuineScriptCredentials(t *testing.T) {
	t.Parallel()

	positives := []struct {
		content string
		value   string
	}{
		{"AdminPassword=Synthetic-Admin-123!\n", "Synthetic-Admin-123!"},
		{"Password=Synthetic-Password-123!\n", "Synthetic-Password-123!"},
		{"$SvcPass = \"Synthetic-Service-123!\"\n", "Synthetic-Service-123!"},
		{"export RUN_PASSWORD=Synthetic-Run-123!\n", "Synthetic-Run-123!"},
	}
	for _, test := range positives {
		candidates := Harvest(HarvestInput{Content: []byte(test.content), Path: "deploy.ps1"})
		if candidateForValue(candidates, test.value) == nil {
			t.Errorf("expected credential value %q to be retained for %q, got %#v", test.value, test.content, candidates)
		}
	}
}

func TestNonSecretValueShapeClassifiesFragments(t *testing.T) {
	t.Parallel()

	rejected := []string{
		"@var",
		":bind_value",
		"func(column_a, 1, 2)",
		"field,,type(255)",
		"value and",
		"plain words here",
		"several plain words",
		"account label text",
	}
	for _, value := range rejected {
		if reason, reject := NonSecretValueShape(value); !reject {
			t.Errorf("NonSecretValueShape(%q) = false (%s), want rejected", value, reason)
		}
	}

	accepted := []string{
		"Synthetic-Admin-123!",
		"CorrectHorse123!",
		"P@ssw0rd!",
		"Winter2026!",
		`os.environ["PASSWORD"]`,
		"${PASSWORD}",
		"svc_backup",
		"CONTOSO\\svc",
	}
	for _, value := range accepted {
		if reason, reject := NonSecretValueShape(value); reject {
			t.Errorf("NonSecretValueShape(%q) = rejected (%s), want accepted", value, reason)
		}
	}
}
