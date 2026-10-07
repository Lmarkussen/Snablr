package dbinspect

import (
	"strings"
	"testing"
)

func inspectConfigText(name, text string) []Match {
	candidate := Candidate{FilePath: name, Name: name, Extension: strings.ToLower(fileExt(name)), Size: int64(len(text))}
	return New().InspectContent(candidate, []byte(text))
}

func fileExt(name string) string {
	if index := strings.LastIndex(name, "."); index >= 0 {
		return name[index:]
	}
	return ""
}

func hasRuleMatch(matches []Match, id string) bool {
	for _, match := range matches {
		if match.ID == id {
			return true
		}
	}
	return false
}

func TestConnectionStringRegressions(t *testing.T) {
	t.Parallel()

	t.Run("realistic connection string extracts a credential", func(t *testing.T) {
		t.Parallel()
		text := "ConnectionString=Server=db.example.test;User ID=svc_app;Password=Synthetic-DB-123!;\n"
		matches := inspectConfigText("app.config", text)
		if !hasRuleMatch(matches, "dbinspect.access.connection_string") {
			t.Fatalf("expected database connection credential, got %#v", matches)
		}
		for _, match := range matches {
			if match.ID == "dbinspect.access.connection_string" && !strings.EqualFold(match.Severity, "high") {
				t.Fatalf("realistic connection string severity = %s, want high", match.Severity)
			}
		}
	})

	t.Run("obvious sample connection string stays quiet", func(t *testing.T) {
		t.Parallel()
		text := "ConnectionString=Server=MySQLServerName;User ID=MyUserID;Password=MyPassword;\n"
		matches := inspectConfigText("sample.config", text)
		// No credential may be produced from vendor sample values. A non-secret
		// server indicator is acceptable.
		if hasRuleMatch(matches, "dbinspect.access.connection_string") {
			t.Fatalf("sample connection string produced a credential: %#v", matches)
		}
	})

	t.Run("schema-like password metadata is not a credential", func(t *testing.T) {
		t.Parallel()
		text := "ConnectionString=Server=db.example.test;User ID=svc_app;Password=field,,type(255);\n"
		matches := inspectConfigText("schema.config", text)
		// No high-severity credential may be produced from metadata syntax.
		for _, match := range matches {
			if match.ID == "dbinspect.access.connection_string" && strings.EqualFold(match.Severity, "high") {
				t.Fatalf("metadata-shaped password produced a high-severity credential: %#v", match)
			}
		}
	})
}
