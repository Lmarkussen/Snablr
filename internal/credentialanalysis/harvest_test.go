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

func TestHarvestSuppressesPlaceholdersAndConfirmsEnvironmentPairs(t *testing.T) {
	got := Harvest(HarvestInput{Content: []byte("DB_USERNAME=svc\nDB_PASSWORD=secret\nTEMPLATE_PASSWORD=${PASSWORD}\n"), Path: "service.env"})
	if !hasCandidate(got, Confirmed, "secret") {
		t.Fatalf("environment candidates incorrect: %#v", got)
	}
	if hasCandidate(got, Confirmed, "${PASSWORD}") || hasCandidate(got, Review, "${PASSWORD}") {
		t.Fatalf("template value was not suppressed from credential material: %#v", got)
	}
}

func TestHarvestPairsAdjacentTopLevelCredentialFieldsWithoutCrossProduct(t *testing.T) {
	got := Harvest(HarvestInput{Content: []byte("username=alice\npassword=AlicePass!\n\naccount=bob\npassword=BobPass!\n"), Path: "records.txt"})
	if !hasIdentityValue(got, Confirmed, "alice", "AlicePass!") || !hasIdentityValue(got, Confirmed, "bob", "BobPass!") {
		t.Fatalf("explicit adjacent records were not paired: %#v", got)
	}
	for _, candidate := range got {
		if candidate.Verification == Confirmed && candidate.Identity == "alice" && candidate.Value == "BobPass!" {
			t.Fatal("cross-record credential pairing was created")
		}
	}
}

func TestHarvestPairsLabeledAccountAndPassword(t *testing.T) {
	got := Harvest(HarvestInput{Content: []byte("Deployment account: SYNTHETIC\\svc-r4b\nPassword: R4B-Example-922!\n"), Path: "plain.txt"})
	if !hasIdentityValue(got, Confirmed, `SYNTHETIC\svc-r4b`, "R4B-Example-922!") {
		t.Fatalf("labeled account/password was not paired: %#v", got)
	}
}

func TestHarvestRecognizesCompoundEnvironmentPasswordAsReview(t *testing.T) {
	got := Harvest(HarvestInput{Content: []byte("R4B_PASSWORD_ONLY=R4B-Review-Only-771!\n"), Path: "review.env"})
	if !hasCandidate(got, Review, "R4B-Review-Only-771!") {
		t.Fatalf("compound environment password was not retained for review: %#v", got)
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

func TestHarvestStructuredConfigurationScopes(t *testing.T) {
	tests := []struct {
		name, path, content string
		pairs               [][2]string
	}{
		{
			name: "toml array tables", path: "services.toml",
			content: "[[services]]\nusername = \"Notus481\"\npassword = \"TOML-A!\"\n\n[[services]]\nusername = \"Komtek72\"\npassword = \"TOML-B!\"\n",
			pairs:   [][2]string{{"Notus481", "TOML-A!"}, {"Komtek72", "TOML-B!"}},
		},
		{
			name: "properties namespaces", path: "application.properties",
			content: "alpha.username=svc-alpha\nalpha.password=Alpha-Pass!\nbeta.username=svc-beta\nbeta.password=Beta-Pass!\n",
			pairs:   [][2]string{{"svc-alpha", "Alpha-Pass!"}, {"svc-beta", "Beta-Pass!"}},
		},
	}
	for _, test := range tests {
		got := Harvest(HarvestInput{Content: []byte(test.content), Path: test.path})
		for _, pair := range test.pairs {
			if !hasIdentityValue(got, Confirmed, pair[0], pair[1]) {
				t.Errorf("%s: missing pair %q/%q: %#v", test.name, pair[0], pair[1], got)
			}
		}
	}
}

func TestHarvestStructuredConfigurationDoesNotCrossScopes(t *testing.T) {
	content := "[[accounts]]\nusername = \"alice\"\npassword = \"Alice-Pass!\"\n\n[[accounts]]\nusername = \"bob\"\npassword = \"Bob-Pass!\"\n"
	got := Harvest(HarvestInput{Content: []byte(content), Path: "accounts.toml"})
	if !hasIdentityValue(got, Confirmed, "alice", "Alice-Pass!") || !hasIdentityValue(got, Confirmed, "bob", "Bob-Pass!") {
		t.Fatalf("expected scoped TOML pairs: %#v", got)
	}
	for _, candidate := range got {
		if candidate.Verification == Confirmed && ((candidate.Identity == "alice" && candidate.Value == "Bob-Pass!") || (candidate.Identity == "bob" && candidate.Value == "Alice-Pass!")) {
			t.Fatalf("cross-scope TOML pair created: %#v", candidate)
		}
	}
}

func TestHarvestStructuredConfigurationPreservesUnicodeAndRejectsPlaceholders(t *testing.T) {
	content := "norsk.username=bruker-æøå\nnorsk.password=Passord-æøå!\nignored.username=%APP_USER%\nignored.password=${APP_PASSWORD}\n"
	got := Harvest(HarvestInput{Content: []byte(content), Path: "norsk.properties"})
	if !hasIdentityValue(got, Confirmed, "bruker-æøå", "Passord-æøå!") {
		t.Fatalf("unicode properties pair missing: %#v", got)
	}
	if hasIdentityValue(got, Confirmed, "%APP_USER%", "${APP_PASSWORD}") {
		t.Fatal("placeholder properties pair was confirmed")
	}
}

func TestHarvestXMLAttributeCredentialScope(t *testing.T) {
	content := `<configuration><account username="xml-user" password="Xml-Pass!"/><account username="other-user" password="Other-Pass!"/></configuration>`
	got := Harvest(HarvestInput{Content: []byte(content), Path: "accounts.xml"})
	if !hasIdentityValue(got, Confirmed, "xml-user", "Xml-Pass!") || !hasIdentityValue(got, Confirmed, "other-user", "Other-Pass!") {
		t.Fatalf("XML attribute pairs were not preserved: %#v", got)
	}
	for _, candidate := range got {
		if candidate.Verification == Confirmed && ((candidate.Identity == "xml-user" && candidate.Value == "Other-Pass!") || (candidate.Identity == "other-user" && candidate.Value == "Xml-Pass!")) {
			t.Fatalf("cross-node XML pair created: %#v", candidate)
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

func hasIdentityValue(candidates []Candidate, verification Verification, identity, value string) bool {
	for _, candidate := range candidates {
		if candidate.Verification == verification && candidate.Identity == identity && candidate.Value == value {
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

func TestHarvestCommandLineCredentialPairs(t *testing.T) {
	content := strings.Join([]string{
		"some-tool -u test -p test123",
		"some-tool --username Notus482 --password ExamplePass!42 --verbose",
		"tool.exe /user:SYNTHETIC\\svc-deploy /password:Example123!",
		`deployment -u "domain user" --flag value -p "Example Pass 482!"`,
		`tool --user=Komtek17 --pass='Synthetic#492!'`,
		`tool -u continued-user \\`,
		`  -p ContinuedPass!`,
	}, "\n")
	got := Harvest(HarvestInput{Content: []byte(content), Path: "commands.txt"})
	for _, want := range [][2]string{
		{"test", "test123"}, {"Notus482", "ExamplePass!42"}, {`SYNTHETIC\svc-deploy`, "Example123!"},
		{"domain user", "Example Pass 482!"}, {"Komtek17", "Synthetic#492!"}, {"continued-user", "ContinuedPass!"},
	} {
		if !hasIdentityValue(got, Confirmed, want[0], want[1]) {
			t.Errorf("missing command pair %q/%q: %#v", want[0], want[1], got)
		}
	}
}

func TestHarvestCommandLinesDoNotCrossPairOrConfirmPlaceholders(t *testing.T) {
	content := "tool -u alice -p AlicePass!\ntool -u bob -p BobPass!\nusage: tool -u USER -p PASSWORD\n"
	got := Harvest(HarvestInput{Content: []byte(content), Path: "commands.txt"})
	if !hasIdentityValue(got, Confirmed, "alice", "AlicePass!") || !hasIdentityValue(got, Confirmed, "bob", "BobPass!") {
		t.Fatalf("explicit command pairs missing: %#v", got)
	}
	for _, candidate := range got {
		if candidate.Verification == Confirmed && ((candidate.Identity == "alice" && candidate.Value == "BobPass!") || (candidate.Identity == "bob" && candidate.Value == "AlicePass!")) {
			t.Fatalf("cross-command pair created: %#v", candidate)
		}
		if candidate.Identity == "USER" || candidate.Value == "PASSWORD" {
			t.Fatalf("usage placeholders became credential material: %#v", candidate)
		}
	}
}

func TestHarvestStructuredAccountNameAlias(t *testing.T) {
	for _, item := range []struct {
		path, content, identity, password string
	}{
		{"alias.json", `{"credential":{"account_name":"json-user","account_password":"Json-Pass!"}}`, "json-user", "Json-Pass!"},
		{"alias.yaml", "credentials:\n  account_name: yaml-user\n  user_password: Yaml-Pass!\n", "yaml-user", "Yaml-Pass!"},
		{"alias.xml", `<account><account_name>xml-user</account_name><user_password>Xml-Pass!</user_password></account>`, "xml-user", "Xml-Pass!"},
	} {
		got := Harvest(HarvestInput{Content: []byte(item.content), Path: item.path})
		if !hasIdentityValue(got, Confirmed, item.identity, item.password) {
			t.Errorf("%s: account_name alias was not paired: %#v", item.path, got)
		}
	}
}
