package credentialaudit

import "testing"

func TestNormalizeArchiveMemberPath(t *testing.T) {
	if got := BaseSourcePath(`\\host\share\bundle.zip!nested\credentials.ini`); got != "//host/share/bundle.zip" {
		t.Fatalf("base path = %q", got)
	}
}

func TestExtractPairsConnectionFormatsAndGuards(t *testing.T) {
	tests := []struct {
		name, typ, value, username, password string
		want                                 bool
	}{
		{"sql", "connection_string", "Server=db;User ID=svc;Password=Sql!;", "svc", "Sql!", true},
		{"odbc", "dsn", "Driver=x;UID=svc;PWD={P;ass};", "svc", "P;ass", true},
		{"postgres", "connection_string", "postgresql://svc:p%40ss@db/app", "svc", "p@ss", true},
		{"mysql", "connection_string", "mysql://svc:p%21@db/app", "svc", "p!", true},
		{"no-user", "connection_string", "Server=db;Password=secret;", "", "", false},
		{"integrated", "connection_string", "Server=db;Integrated Security=true;", "", "", false},
		{"opaque", "password", "opaque-user", "", "", false},
		{"hash", "nt_hash", "0123456789abcdef0123456789abcdef", "", "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pairs := ExtractPairs(ObservedMaterial{MaterialType: test.typ, Identity: test.username, Value: test.value})
			if (len(pairs) > 0) != test.want {
				t.Fatalf("pairs = %#v, want=%v", pairs, test.want)
			}
			if test.want && (pairs[0].Username != test.username || pairs[0].Password != test.password) {
				t.Fatalf("pair = %#v", pairs[0])
			}
		})
	}
}

func TestCompareSeparatesDuplicatesMembersAndTypes(t *testing.T) {
	expected := []ExpectedPair{
		{ID: "one", SourcePath: "bundle.zip", Username: "user", Password: "pass"},
		{ID: "two", SourcePath: "bundle.zip", Username: "other", Password: "same"},
	}
	observed := []ObservedMaterial{
		{RowID: "r1", MaterialType: "password", SourcePath: "bundle.zip!a.ini", Identity: "user", Value: "pass"},
		{RowID: "r2", MaterialType: "password", SourcePath: "bundle.zip!b.ini", Identity: "other", Value: "same"},
		{RowID: "r3", MaterialType: "nt_hash", SourcePath: "bundle.zip!a.ini", Identity: "user", Value: "pass"},
	}
	report := Compare(expected, observed)
	if len(report.Matches) != 2 || len(report.MissingIDs) != 0 || report.UniqueMatched != 2 {
		t.Fatalf("report = %#v", report)
	}
}

func TestCompareDoesNotCreditUnrelatedPassword(t *testing.T) {
	report := Compare([]ExpectedPair{{ID: "want", SourcePath: "a.ini", Username: "user", Password: "pass"}}, []ObservedMaterial{{RowID: "wrong", MaterialType: "password", SourcePath: "a.ini", Identity: "other", Value: "pass"}})
	if len(report.Matches) != 0 || len(report.MissingIDs) != 1 {
		t.Fatalf("report = %#v", report)
	}
}
