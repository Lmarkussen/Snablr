package seed

import "testing"

func TestValidateSQLiteSeedRejectsPlaceholder(t *testing.T) {
	t.Parallel()

	content := []byte("SYNTHETIC SQLITE PLACEHOLDER\n")
	err := validateSQLiteSeed(content, "sqlite-credential-db", renderContext{})
	if err == nil {
		t.Fatal("expected placeholder SQLite seed to be rejected")
	}
}

func TestValidateSQLiteSeedAcceptsRealDatabase(t *testing.T) {
	t.Parallel()

	content := renderSQLiteSeed("sqlite-credential-db", renderContext{
		Token: "001_0001",
	})
	if err := validateSQLiteSeed(content, "sqlite-credential-db", renderContext{
		Token: "001_0001",
	}); err != nil {
		t.Fatalf("expected real SQLite seed to validate, got %v", err)
	}
}
