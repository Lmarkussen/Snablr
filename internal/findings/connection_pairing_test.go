package findings

import (
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/viewport"
	"snablr/internal/credentialanalysis"
)

func connectionCandidate(value string) credentialanalysis.Candidate {
	return credentialanalysis.Candidate{CredentialType: "connection_string", Value: value, Verification: credentialanalysis.Confirmed, Path: "config/database.conf", Host: "HOST", Share: "share"}
}

func TestConnectionPairSQLServerAndODBCForms(t *testing.T) {
	tests := []struct {
		name, value, username, password, server, database string
	}{
		{"sql server", "Provider=SQLOLEDB;Data Source=sql01.synthetic;Initial Catalog=AuditDb;User ID=sql-user;Password=SqlSecret!;", "sql-user", "SqlSecret!", "sql01.synthetic", "AuditDb"},
		{"uid pwd", "Server=sql02;Database=Audit;UID=uid-user;PWD=uid-secret!;", "uid-user", "uid-secret!", "sql02", "Audit"},
		{"quoted semicolon", `Server=sql03;User ID={quoted-user};Password={pa;ss!};`, "quoted-user", "pa;ss!", "sql03", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pair, ok := deriveConnectionPair(connectionCandidate(test.value))
			if !ok || pair.Username != test.username || pair.Password != test.password || pair.Server != test.server || pair.Database != test.database {
				t.Fatalf("pair = %#v, ok=%v", pair, ok)
			}
		})
	}
}

func TestConnectionPairPostgresURIsDecodeExactlyOnce(t *testing.T) {
	for _, value := range []string{
		"postgresql://pg-user:PgSecret%21@pg01.synthetic:5432/audit?sslmode=require",
		"postgres://unicode%C3%A9:pa%25ss%21@pg02.synthetic/audit",
		"mariadb://maria-user:MariaSecret%21@db.synthetic/audit",
		"sqlserver://sql-user:SqlSecret%21@db.synthetic/audit",
	} {
		pair, ok := deriveConnectionPair(connectionCandidate(value))
		if !ok {
			t.Fatalf("URI was not accepted: %s", value)
		}
		if pair.Username == "" || pair.Password == "" || pair.Server == "" || pair.Database == "" {
			t.Fatalf("incomplete URI pair: %#v", pair)
		}
		if strings.Contains(pair.Password, "%21") || strings.Contains(pair.Username, "%C3") {
			t.Fatalf("URI was not decoded exactly once: %#v", pair)
		}
	}
}

func TestConnectionPairPostgresKeywordValue(t *testing.T) {
	pair, ok := parseKeywordConnection("host='db synthetic' dbname=app user=svc-user password='R4C4 Password 482!'")
	if !ok || pair.Username != "svc-user" || pair.Password != "R4C4 Password 482!" || pair.Server != "db synthetic" || pair.Database != "app" {
		t.Fatalf("pair = %#v, ok=%v", pair, ok)
	}
}

func TestConnectionPairRejectsAmbiguousOrNonPasswordAuthentication(t *testing.T) {
	for _, value := range []string{
		"Server=sql;Integrated Security=true;User ID=ignored;Password=ignored!;",
		"Server=sql;User ID=one;UID=two;Password=secret!;",
		"Server=sql;User ID=user;Password=${DB_PASSWORD};",
		"postgresql://user@host/db",
		"not a database connection string",
	} {
		if pair, ok := deriveConnectionPair(connectionCandidate(value)); ok {
			t.Fatalf("unexpected pair %#v for %q", pair, value)
		}
	}
}

func TestConnectionPairKeepsOriginalMaterialAndPresentsDerivedPair(t *testing.T) {
	value := "Provider=SQLOLEDB;Data Source=sql01.synthetic;Initial Catalog=AuditDb;User ID=sql-user;Password=SqlSecret!;"
	candidate := connectionCandidate(value)
	categories := buildCategories([]Credential{{CredentialKey: "connection-row", Candidate: candidate}}, nil, nil)
	if len(categories) != 1 || categories[0].Name != "Connection & Database Secrets" {
		t.Fatalf("categories = %#v", categories)
	}
	d := categories[0].Discoveries[0]
	if d.Identity != "sql-user" || d.RecoveredPassword != "SqlSecret!" || d.Value != value {
		t.Fatalf("discovery lost original or derived values: %#v", d)
	}
	if d.PairingStatus != "Confirmed pair (Finder-derived)" || len(d.PersistedRefs) != 1 || d.PersistedRefs[0] != "connection-row" {
		t.Fatalf("pairing = %#v", d)
	}
	m := &model{scans: []Scan{{ID: "scan"}}, categories: categories, screen: screenDiscoveries, discoveries: categories[0].Discoveries, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(160, 50)
	text := m.evidenceText()
	for _, want := range []string{"USERNAME + PASSWORD COMBINATION", "Username: sql-user", "Password: SqlSecret!", "Pairing: Confirmed pair (Finder-derived)", "CONNECTION STRING FIELDS", "Server / Host: sql01.synthetic", "Original"} {
		if !strings.Contains(text, want) {
			t.Fatalf("evidence missing %q: %q", want, text)
		}
	}
}

func TestConnectionPairDetailsPreservePostgresTarget(t *testing.T) {
	candidate := connectionCandidate("postgresql://pg-user:PgSecret%21@pg01.synthetic:5432/audit")
	details := connectionDetails(candidate)
	joined := make([]string, 0, len(details))
	for _, detail := range details {
		joined = append(joined, detail.Label+": "+detail.Value)
	}
	text := strings.Join(joined, "\n")
	for _, want := range []string{"Provider / Driver: postgresql", "Server / Host: pg01.synthetic", "Port: 5432", "Database / Catalog: audit", "Username: pg-user", "Password: PgSecret!"} {
		if !strings.Contains(text, want) {
			t.Fatalf("details missing %q: %q", want, text)
		}
	}
}
