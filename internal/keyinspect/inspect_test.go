package keyinspect

import "testing"

func TestInspectorNeedsContentForExactPrivateKeyFilenames(t *testing.T) {
	t.Parallel()

	inspector := New()
	if !inspector.NeedsContent(Candidate{Name: "id_rsa"}) {
		t.Fatal("expected exact private key filename to request content")
	}
	if inspector.NeedsContent(Candidate{Name: "notes.txt"}) {
		t.Fatal("expected non-key filename to skip content")
	}
}

func TestInspectorValidatesPrivateKeyHeader(t *testing.T) {
	t.Parallel()

	inspector := New()
	matches := inspector.InspectContent(Candidate{Name: "id_ed25519"}, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nLAB_ONLY_SYNTHETIC\n-----END OPENSSH PRIVATE KEY-----\n"))
	if len(matches) != 1 {
		t.Fatalf("expected one validated private key match, got %#v", matches)
	}
	match := matches[0]
	if match.ID != "keyinspect.content.private_key_header" || match.SignalType != "validated" {
		t.Fatalf("unexpected match metadata: %#v", match)
	}
	if match.Severity != "critical" || match.Confidence != "high" {
		t.Fatalf("expected critical/high private key validation, got %#v", match)
	}
}

func TestInspectorIgnoresNonKeyTextWithoutHeader(t *testing.T) {
	t.Parallel()

	inspector := New()
	matches := inspector.InspectContent(Candidate{Name: "id_rsa"}, []byte("user=demo\npassword=changeme\n"))
	if len(matches) != 0 {
		t.Fatalf("expected non-key content to stay quiet, got %#v", matches)
	}
}
