package keyinspect

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"
)

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

func TestInspectorRequestsContentForArbitraryExtensionlessName(t *testing.T) {
	t.Parallel()

	if !New().NeedsContent(Candidate{Name: "customer-prod-key", Extension: ""}) {
		t.Fatal("expected arbitrary extensionless name to request bounded key inspection")
	}
}

func TestInspectorStructurallyValidatesArbitraryNamedPEMKey(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	content := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	match := New().InspectContent(Candidate{Name: "customer-prod-key"}, content)
	if len(match) != 1 || match[0].Status != StatusConfirmed || match[0].Algorithm != "RSA/PKCS#8" {
		t.Fatalf("unexpected structural result: %#v", match)
	}
}

func TestInspectorRecognizesEncryptedPEMWithoutDecryption(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(privateKey)
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", der, []byte("synthetic-passphrase"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	match := New().InspectContent(Candidate{Name: "encrypted-backup"}, pem.EncodeToMemory(block))
	if len(match) != 1 || match[0].Status != StatusEncrypted || !match[0].Encrypted {
		t.Fatalf("unexpected encrypted result: %#v", match)
	}
}

func TestInspectorKeepsMalformedCandidateOutOfConfirmedStatus(t *testing.T) {
	t.Parallel()

	content := []byte("-----BEGIN RSA PRIVATE KEY-----\nnot-base64\n-----END RSA PRIVATE KEY-----\n")
	match := New().InspectContent(Candidate{Name: "broken-key"}, content)
	if len(match) != 1 || match[0].Status == StatusConfirmed || match[0].Status != StatusMalformed {
		t.Fatalf("unexpected malformed result: %#v", match)
	}
}

func TestInspectorValidatesOpenSSHPrivateKeyStructurally(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	content, err := ssh.MarshalPrivateKey(privateKey, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	matches := New().InspectContent(Candidate{Name: "arbitrary-key"}, pem.EncodeToMemory(content))
	if len(matches) != 1 || matches[0].Status != StatusConfirmed || matches[0].Format != "OpenSSH" {
		t.Fatalf("unexpected valid OpenSSH result: %#v", matches)
	}
}

func TestInspectorRecognizesEncryptedOpenSSHWithoutDecryption(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	content, err := ssh.MarshalPrivateKeyWithPassphrase(privateKey, "synthetic", []byte("synthetic-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	matches := New().InspectContent(Candidate{Name: "encrypted-open-ssh"}, pem.EncodeToMemory(content))
	if len(matches) != 1 || matches[0].Status != StatusEncrypted || !matches[0].Encrypted {
		t.Fatalf("unexpected encrypted OpenSSH result: %#v", matches)
	}
}

func TestInspectorRejectsAdversarialOpenSSHEnvelopes(t *testing.T) {
	cases := [][]byte{
		[]byte("openssh-key-v1\x00"),
		[]byte("openssh-key-v1\x00\x00\x00\x00"),
		[]byte("openssh-key-v1\x00corrupt-length-fields"),
		[]byte("random-binary-with-openssh-key-v1-prefix"),
	}
	for index, body := range cases {
		content := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: body})
		matches := New().InspectContent(Candidate{Name: "adversarial-key"}, content)
		if len(matches) != 1 || matches[0].Status == StatusConfirmed {
			t.Fatalf("case %d was incorrectly confirmed: %#v", index, matches)
		}
	}
}
