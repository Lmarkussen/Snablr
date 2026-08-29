package credentialanalysis

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestHarvestStructuredAndReviewMaterial(t *testing.T) {
	content := []byte(`{"username":"svc","password":"literal"}`)
	got := Harvest(HarvestInput{Content: content, Path: "config.json"})
	if !hasCandidate(got, Confirmed, "literal") {
		t.Fatalf("structured JSON credential was not harvested")
	}
	got = Harvest(HarvestInput{Content: []byte("username=svc\n" + strings.Repeat("unrelated\n", 20) + "password=distant"), Path: "notes.txt"})
	if !hasCandidate(got, Review, "distant") {
		t.Fatalf("standalone/distant secret was not retained for review")
	}
	for _, candidate := range got {
		if candidate.Verification == Confirmed {
			t.Fatalf("distant values were incorrectly confirmed: %#v", candidate)
		}
	}
}

func TestHarvestRecognizesPlaceholdersAndEnvironmentPairs(t *testing.T) {
	got := Harvest(HarvestInput{Content: []byte("DB_USERNAME=svc\nDB_PASSWORD=secret\nTEMPLATE_PASSWORD=${PASSWORD}\n"), Path: "service.env"})
	if !hasCandidate(got, Confirmed, "secret") || !hasCandidate(got, Review, "${PASSWORD}") {
		t.Fatalf("environment candidates incorrect: %#v", got)
	}
}

func TestHarvestRecognizesStructuredAPIPairs(t *testing.T) {
	got := Harvest(HarvestInput{Content: []byte(`{"access_key_id":"AKIA0000000000000001","secret_access_key":"api-secret"}`), Path: "api.json"})
	if !hasCandidate(got, Confirmed, "api-secret") {
		t.Fatalf("structured API pair was not confirmed: %#v", got)
	}
	got = Harvest(HarvestInput{Content: []byte("api_key=standalone\n"), Path: "api.env"})
	if !hasCandidate(got, Review, "standalone") {
		t.Fatal("standalone API material was not retained for review")
	}
}

func TestHarvestFormatsAndSemanticNoise(t *testing.T) {
	tests := []struct {
		name, path, content, wantValue string
		verification                   Verification
	}{
		{"xml", "web.config", `<configuration><add key="Username" value="svc"/><add key="Password" value="xml-secret"/></configuration>`, "xml-secret", Confirmed},
		{"ini", "app.ini", "[service]\nuser=svc\npassword=ini-secret\n", "ini-secret", Confirmed},
		{"yaml", "app.yaml", "service:\n  username: svc\n  password: yaml-secret\n", "yaml-secret", Confirmed},
		{"script literal", "config.py", `password = "script-secret"`, "script-secret", Review},
		{"script reference", "config.py", `password = os.environ["PASSWORD"]`, `os.environ["PASSWORD"]`, Review},
	}
	for _, test := range tests {
		got := Harvest(HarvestInput{Content: []byte(test.content), Path: test.path})
		if !hasCandidate(got, test.verification, test.wantValue) {
			t.Errorf("%s: expected %s candidate %q, got %#v", test.name, test.verification, test.wantValue, got)
		}
	}
	noise := Harvest(HarvestInput{Content: []byte("sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\nuuid=123e4567-e89b-12d3-a456-426614174000\nbase64=YWJjZGVmZ2hpamtsbW5vcA==\n"), Path: "checksums.txt"})
	for _, candidate := range noise {
		if candidate.CredentialType != "" {
			t.Fatalf("entropy-only material became a candidate: %#v", candidate)
		}
	}
}

func TestHarvestPreservesAPIFieldTypesAndEncryptedKeys(t *testing.T) {
	got := Harvest(HarvestInput{Content: []byte(`{"api_key":"key-value","client_secret":"client-value","bearer_token":"bearer-value","access_key":"access-value","secret_key":"secret-value","token":"generic-value"}`), Path: "api.json"})
	want := map[string]string{
		"key-value": "api_key", "client-value": "client_secret", "bearer-value": "bearer_token",
		"access-value": "access_key", "secret-value": "secret_key", "generic-value": "token",
	}
	for value, typ := range want {
		found := false
		for _, candidate := range got {
			if candidate.Value == value && candidate.CredentialType == typ {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s value %q, got %#v", typ, value, got)
		}
	}
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("encrypted-envelope")})
	keys := Harvest(HarvestInput{Content: encrypted, Path: "encrypted.pem"})
	if len(keys) != 1 || keys[0].Verification != Confirmed || !keys[0].Encrypted || keys[0].Value != string(encrypted) {
		t.Fatalf("encrypted private key was not preserved as confirmed material: %#v", keys)
	}
}

func TestHarvestValidatesPrivateKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	if !hasPrivateKeyCandidate(Harvest(HarvestInput{Content: rsaPEM, Path: "id_rsa.pem"}), Confirmed, "RSA PRIVATE KEY") {
		t.Fatal("valid RSA key was not confirmed")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPEM, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	if !hasPrivateKeyCandidate(Harvest(HarvestInput{Content: pem.EncodeToMemory(sshPEM), Path: "id_ed25519"}), Confirmed, "OPENSSH PRIVATE KEY") {
		t.Fatal("valid OpenSSH key was not confirmed")
	}
	fake := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\ntotally fake\n-----END OPENSSH PRIVATE KEY-----")
	fakeCandidates := Harvest(HarvestInput{Content: fake, Path: "fake.key"})
	if len(fakeCandidates) != 1 || fakeCandidates[0].Verification != Review || fakeCandidates[0].CredentialType != "private_key" {
		t.Fatalf("malformed key was not retained for review: %#v", fakeCandidates)
	}
}

func hasCandidate(candidates []Candidate, verification Verification, value string) bool {
	for _, candidate := range candidates {
		if candidate.Verification == verification && candidate.Value == value {
			return true
		}
	}
	return false
}

func hasPrivateKeyCandidate(candidates []Candidate, verification Verification, marker string) bool {
	for _, candidate := range candidates {
		if candidate.Verification == verification && candidate.CredentialType == "private_key" && strings.Contains(candidate.Value, marker) {
			return true
		}
	}
	return false
}
