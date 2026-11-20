package jenkinsinspect

import (
	"encoding/hex"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	hudson, err := hex.DecodeString(testHudsonSecret)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := SecretKey([]byte(testMasterKey+"\n"), hudson)
	if !ok {
		t.Fatal("secret key not derived")
	}
	return key
}

func TestDecryptJenkinsSecrets(t *testing.T) {
	key := testKey(t)
	for value, want := range map[string]string{
		testPasswordNew:    "Tr4in-Jenk-2026!",
		testSecretNew:      "build-token-SYNTHETIC-8842",
		testPasswordLegacy: "Legacy-Jenk-0417",
	} {
		got, ok := Decrypt(key, value)
		if !ok || got != want {
			t.Errorf("Decrypt(%.20s...) = %q, %v; want %q", value, got, ok, want)
		}
	}
	if got, ok := Decrypt(key, testOtherKeyValue); ok {
		t.Errorf("value under another key decrypted to %q", got)
	}
	if _, ok := Decrypt(key, "{AQAAABAAAAAQ}"); ok {
		t.Error("truncated value decrypted")
	}
}

func TestSecretKeyNeedsTheMatchingMasterKey(t *testing.T) {
	hudson, _ := hex.DecodeString(testHudsonSecret)
	if _, ok := SecretKey([]byte("00"+testMasterKey[2:]), hudson); ok {
		t.Error("wrong master.key accepted")
	}
	if _, ok := SecretKey([]byte(testMasterKey), hudson[:len(hudson)-1]); ok {
		t.Error("truncated hudson.util.Secret accepted")
	}
}

func TestSecretsArePairedWithTheirCredential(t *testing.T) {
	credentials := `<?xml version='1.1' encoding='UTF-8'?>
<com.cloudbees.plugins.credentials.SystemCredentialsProvider plugin="credentials@1311.vcf0a_900b_37c2">
  <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash">
    <entry>
      <com.cloudbees.plugins.credentials.domains.Domain><specifications/></com.cloudbees.plugins.credentials.domains.Domain>
      <java.util.concurrent.CopyOnWriteArrayList>
        <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
          <scope>GLOBAL</scope>
          <id>deploy-svc</id>
          <description>deployment account</description>
          <username>CORP\svc_build</username>
          <password>` + testPasswordNew + `</password>
          <usernameSecret>false</usernameSecret>
        </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
        <org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl>
          <scope>GLOBAL</scope>
          <id>artifact-token</id>
          <secret>` + testSecretNew + `</secret>
        </org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl>
      </java.util.concurrent.CopyOnWriteArrayList>
    </entry>
  </domainCredentialsMap>
</com.cloudbees.plugins.credentials.SystemCredentialsProvider>`
	secrets := Secrets([]byte(credentials))
	if len(secrets) != 2 {
		t.Fatalf("got %d secrets: %+v", len(secrets), secrets)
	}
	if s := secrets[0]; s.Field != "password" || s.Username != `CORP\svc_build` || s.CredentialID != "deploy-svc" {
		t.Errorf("password secret: %+v", s)
	}
	if s := secrets[1]; s.Field != "secret" || s.Username != "" || s.CredentialID != "artifact-token" {
		t.Errorf("secret text must not borrow another credential's username: %+v", s)
	}

	// Plain text values and ordinary base64 outside secret fields are not
	// Jenkins secrets.
	other := `<config><description>U29tZSBkZXNjcmlwdGlvbiB0ZXh0IGhlcmU=</description><password>${DEPLOY_PASSWORD}</password></config>`
	if got := Secrets([]byte(other)); len(got) != 0 {
		t.Errorf("non-secrets listed: %+v", got)
	}
}
