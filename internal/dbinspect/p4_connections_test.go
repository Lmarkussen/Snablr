package dbinspect

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func TestStructuredDatabaseConfigurationMatrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		text string
	}{
		{"json", `{"database":{"host":"db.example","port":5432,"name":"payroll"}}`},
		{"yaml", "database:\n  host: db.example\n  port: 5432\n  name: payroll\n"},
		{"xml", `<connection server="db.example" database="payroll" port="5432" />`},
		{"properties", "database.host=db.example\ndatabase.port=5432\ndatabase.name=payroll\n"},
		{"environment", "DATABASE_HOST=db.example\nDATABASE_PORT=5432\nDATABASE_NAME=payroll\n"},
	}
	for _, testCase := range cases {
		matches := inspectConfigText(testCase.name, testCase.text)
		var found *Match
		for index := range matches {
			if matches[index].ID == "dbinspect.infrastructure.structured_config" {
				found = &matches[index]
				break
			}
		}
		if found == nil {
			t.Fatalf("%s: expected configured endpoint, got %#v", testCase.name, matches)
		}
		if found.MatchedText != testCase.text || !strings.Contains(found.Match, "database=payroll") {
			t.Fatalf("%s: raw/configured evidence mismatch: %#v", testCase.name, found)
		}
	}
}

func TestStructuredDatabaseConfigurationRejectsWeakAndPartialText(t *testing.T) {
	t.Parallel()

	for _, text := range []string{
		"This document discusses database servers and connection terminology.",
		"database:\n  host: db.example\n",
		"DATABASE_HOST=db.example\nDATABASE_PORT=5432\n",
	} {
		matches := inspectConfigText("notes.txt", text)
		if hasRuleMatch(matches, "dbinspect.infrastructure.structured_config") {
			t.Fatalf("weak or partial text produced configured endpoint: %#v", matches)
		}
	}
}

func TestStructuredDatabaseConfigurationKeepsConnectionScopesSeparate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		text string
		want []string
	}{
		{
			name: "json",
			text: `{"connections":{"production":{"host":"prod-db","database":"prod"},"reporting":{"host":"report-db","database":"reports"}}}`,
			want: []string{"host=prod-db;database=prod", "host=report-db;database=reports"},
		},
		{
			name: "yaml",
			text: "production:\n  host: prod-db\n  database: prod\nreporting:\n  host: report-db\n  database: reports\n",
			want: []string{"host=prod-db;database=prod", "host=report-db;database=reports"},
		},
		{
			name: "xml",
			text: `<connections><connection server="prod-db" database="prod"/><connection server="report-db" database="reports"/></connections>`,
			want: []string{"server=prod-db;database=prod", "server=report-db;database=reports"},
		},
		{
			name: "properties",
			text: "production.host=prod-db\nproduction.database=prod\nreporting.host=report-db\nreporting.database=reports\n",
			want: []string{"host=prod-db;database=prod", "host=report-db;database=reports"},
		},
		{
			name: "environment",
			text: "PROD_DB_HOST=prod-db\nPROD_DB_NAME=prod\nREPORT_DB_HOST=report-db\nREPORT_DB_NAME=reports\n",
			want: []string{"host=prod-db;database=prod", "host=report-db;database=reports"},
		},
	}
	for _, testCase := range cases {
		matches := inspectConfigText(testCase.name, testCase.text)
		var summaries []string
		for _, match := range matches {
			if match.ID == "dbinspect.infrastructure.structured_config" {
				summaries = append(summaries, match.Match)
				if match.MatchedText != testCase.text {
					t.Fatalf("%s: source evidence changed: %#v", testCase.name, match)
				}
			}
		}
		if len(summaries) != 2 {
			t.Fatalf("%s: got %d observations, want 2: %#v", testCase.name, len(summaries), matches)
		}
		for _, expected := range testCase.want {
			found := false
			for _, summary := range summaries {
				if strings.Contains(summary, expected) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("%s: missing scoped observation %q in %#v", testCase.name, expected, summaries)
			}
		}
	}

	if matches := inspectConfigText("wrong-scope.properties", "production.host=prod-db\nreporting.database=reports\n"); hasRuleMatch(matches, "dbinspect.infrastructure.structured_config") {
		t.Fatalf("cross-scope fields produced a configured endpoint: %#v", matches)
	}
}

func TestStructuredDatabaseConfigurationPreservesIdenticalObservationsByPosition(t *testing.T) {
	t.Parallel()

	text := `{"connections":[{"host":"same-db","database":"app"},{"host":"same-db","database":"app"}]}`
	matches := inspectConfigText("connections.json", text)
	var observations []Match
	for _, match := range matches {
		if match.ID == "dbinspect.infrastructure.structured_config" {
			observations = append(observations, match)
		}
	}
	if len(observations) != 2 {
		t.Fatalf("identical valid observations were collapsed: %#v", matches)
	}
	if observations[0].ObservationID == observations[1].ObservationID {
		t.Fatalf("identical observations did not receive distinct stable IDs: %#v", observations)
	}
	again := inspectConfigText("connections.json", text)
	if len(again) != len(matches) || again[0].ObservationID != matches[0].ObservationID {
		t.Fatalf("observation identity was not deterministic: first=%#v second=%#v", matches, again)
	}
}

func TestSeededStructuredDatabaseConfigurationCorpus(t *testing.T) {
	t.Parallel()

	seeds := []int64{20261030, 20261031, 20261032, 20261033}
	formats := []string{"json", "yaml", "xml", "properties"}
	for _, seed := range seeds {
		seed := seed
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			format := formats[rng.Intn(len(formats))]
			host := fmt.Sprintf("db-%d.example.test", rng.Intn(1000))
			database := fmt.Sprintf("catalog_%d", rng.Intn(1000))
			text := seededConfigText(format, host, database)
			matches := inspectConfigText("opaque-config", text)
			var found *Match
			for index := range matches {
				if matches[index].ID == "dbinspect.infrastructure.structured_config" {
					found = &matches[index]
					break
				}
			}
			if found == nil {
				t.Fatalf("seed %d: valid %s configuration was missed: %#v", seed, format, matches)
			}
			if found.MatchedText != text || found.Snippet != text || found.Context != text {
				t.Fatalf("seed %d: source evidence was not preserved exactly: %#v", seed, found)
			}
			if !strings.Contains(found.Tags[2], "configured") {
				t.Fatalf("seed %d: unexpected status tags: %#v", seed, found.Tags)
			}

			negative := "This sample mentions database servers but has no endpoint fields."
			if hasRuleMatch(inspectConfigText("notes.txt", negative), "dbinspect.infrastructure.structured_config") {
				t.Fatalf("seed %d: prose negative was confirmed", seed)
			}
		})
	}
}

func seededConfigText(format, host, database string) string {
	switch format {
	case "json":
		return fmt.Sprintf(`{"database":{"host":"%s","port":5432,"name":"%s"}}`, host, database)
	case "yaml":
		return fmt.Sprintf("database:\n  host: %s\n  port: 5432\n  name: %s\n", host, database)
	case "xml":
		return fmt.Sprintf(`<connection server="%s" database="%s" port="5432" />`, host, database)
	default:
		return fmt.Sprintf("database.host=%s\ndatabase.port=5432\ndatabase.name=%s\n", host, database)
	}
}
