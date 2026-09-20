package scanner

import (
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/rules"
	"snablr/pkg/logx"
)

type collectingCandidateSink struct {
	candidates []credentialanalysis.Candidate
}

func (c *collectingCandidateSink) RecordCredentialCandidate(candidate credentialanalysis.Candidate) error {
	c.candidates = append(c.candidates, candidate)
	return nil
}

func TestSQLiteInspectorSecretReachesCandidatePipeline(t *testing.T) {
	t.Parallel()

	content := buildSQLiteDBFixture(t, []string{
		`CREATE TABLE users (id INTEGER, username TEXT, password TEXT, api_key TEXT)`,
		`INSERT INTO users VALUES (1, 'svc_finance', 'RotateMeNow!2025', 'SYNTHETIC_API_TOKEN_ONLY_ABC123')`,
	})

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	sink := &collectingCandidateSink{}
	engine.SetCredentialCandidateSink(sink)

	evaluation := engine.Evaluate(FileMetadata{
		Host:      "fs01",
		Share:     "Finance",
		FilePath:  "Apps/finance.sqlite",
		Name:      "finance.sqlite",
		Extension: ".sqlite",
		Size:      int64(len(content)),
	}, content)
	if len(evaluation.Findings) == 0 {
		t.Fatal("expected SQLite findings")
	}
	if len(sink.candidates) < 2 {
		t.Fatalf("expected SQLite secret candidates, got %#v", sink.candidates)
	}

	var sawPassword, sawAPIKey bool
	for _, candidate := range sink.candidates {
		switch candidate.CredentialType {
		case "password":
			if candidate.Value == "RotateMeNow!2025" && candidate.Identity == "svc_finance" {
				sawPassword = true
			}
		case "api_key":
			if candidate.Value == "SYNTHETIC_API_TOKEN_ONLY_ABC123" && candidate.Identity == "svc_finance" {
				sawAPIKey = true
			}
		}
	}
	if !sawPassword || !sawAPIKey {
		t.Fatalf("expected password and api_key candidates, got %#v", sink.candidates)
	}
}

func TestSQLiteBenignRowDoesNotEmitCandidate(t *testing.T) {
	t.Parallel()

	content := buildSQLiteDBFixture(t, []string{
		`CREATE TABLE metrics (id INTEGER, metric_name TEXT, metric_value TEXT)`,
		`INSERT INTO metrics VALUES (1, 'requests_total', '120')`,
	})

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	sink := &collectingCandidateSink{}
	engine.SetCredentialCandidateSink(sink)
	engine.Evaluate(FileMetadata{
		FilePath:  "Apps/benign.sqlite",
		Name:      "benign.sqlite",
		Extension: ".sqlite",
		Size:      int64(len(content)),
	}, content)

	if len(sink.candidates) != 0 {
		t.Fatalf("expected no credential candidate for benign SQLite, got %#v", sink.candidates)
	}
}

func TestPrivateKeyInspectorEmitsRawPrivateKeyCandidate(t *testing.T) {
	t.Parallel()

	content := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==\n-----END OPENSSH PRIVATE KEY-----\n")
	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	sink := &collectingCandidateSink{}
	engine.SetCredentialCandidateSink(sink)

	engine.Evaluate(FileMetadata{
		FilePath:  "Keys/id_ed25519",
		Name:      "id_ed25519",
		Extension: "",
		Size:      int64(len(content)),
	}, content)

	if len(sink.candidates) != 1 {
		t.Fatalf("expected one private-key candidate, got %#v", sink.candidates)
	}
	candidate := sink.candidates[0]
	if candidate.CredentialType != "private_key" || candidate.Value != string(content) {
		t.Fatalf("unexpected private-key candidate: %#v", candidate)
	}
	if candidate.ValidationBasis != "validated_private_key_header" {
		t.Fatalf("unexpected validation basis: %#v", candidate)
	}
}
