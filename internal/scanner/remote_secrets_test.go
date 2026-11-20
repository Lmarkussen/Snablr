package scanner

import (
	"archive/zip"
	"bytes"
	"encoding/hex"
	"path"
	"strings"
	"testing"

	"snablr/internal/credentialanalysis"
)

// Synthetic Jenkins home produced independently with pycryptodome (see
// internal/jenkinsinspect/testvectors_test.go).
const (
	jenkinsMasterKey = "719584624bb836b6236a1becf56c22dc204f37e5775eda542895a88c4c164c0d1db75893e8c8665e5060b05d5e03c68c963d5a3a6e7e0dba6b5e0b9cde858650d47a757afc624567a35e00bc93baf97509844ea9f01b34942bc0d21027dec95448b8566d21060bfec77f420446b1122cb903ec140fe946603dbdfbd49f4f0d5b"
	jenkinsHudsonHex = "2a48ecb47622d7a1f0658e86476cafc0141be5db61e0a69efd6b181d759cfd2788d942c4034a1f64c1620f4a24e505e77f5ff791b68a9877035b87636afa5ca0e1b7e5c1a734259abe24438b14a8520900b641af931fb7e783f81604452d74cee0898066781cff6bacf2f7874317dd925337a66d7fe59fb612d3fa2abc47bbd1d2d4be2b095a6c6045002da468b7584008cd14c3680bbbc9488887ed85f67bab1c9a40e40dbfba5694b4acd655199517b4910679134ac0dc68c697b9ebd0ba399f578d90291391be2206338b78dc03e73dc97593ddd5bedd72b1ba638916443326f61db78ed86f33dfb315c614ed8c62d51ca9348ed0ba6462afbdb56f5bda00eff391c1b7208a1765c6b4c81f61f36f"
	jenkinsPassword  = "{AQAAABAAAAAgRTOyIOxKqSP4le7yKQiB15kMYNt4ur7ytAWWJmRnHAIjYe5DVqa2Miu2tWR9nubv}" // "Tr4in-Jenk-2026!"
	jenkinsToken     = "{AQAAABAAAAAglGT8e3wttIqkfBeyskezCUGpeXBlLjyZw9cEzNZwWS1Fbm2+VcAOrfNzEHZZGF3d}" // "build-token-SYNTHETIC-8842"
)

const jenkinsCredentialsXML = `<?xml version='1.1' encoding='UTF-8'?>
<com.cloudbees.plugins.credentials.SystemCredentialsProvider plugin="credentials@1311">
  <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash">
    <entry>
      <com.cloudbees.plugins.credentials.domains.Domain><specifications/></com.cloudbees.plugins.credentials.domains.Domain>
      <java.util.concurrent.CopyOnWriteArrayList>
        <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
          <scope>GLOBAL</scope>
          <id>deploy-svc</id>
          <username>CORP\svc_build</username>
          <password>` + jenkinsPassword + `</password>
        </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
        <org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl>
          <scope>GLOBAL</scope>
          <id>artifact-token</id>
          <secret>` + jenkinsToken + `</secret>
        </org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl>
      </java.util.concurrent.CopyOnWriteArrayList>
    </entry>
  </domainCredentialsMap>
</com.cloudbees.plugins.credentials.SystemCredentialsProvider>`

type jenkinsFile struct{ path, content string }

func jenkinsHome(t *testing.T, home string) (credentials, master, hudson jenkinsFile) {
	t.Helper()
	raw, err := hex.DecodeString(jenkinsHudsonHex)
	if err != nil {
		t.Fatal(err)
	}
	return jenkinsFile{home + "/credentials.xml", jenkinsCredentialsXML},
		jenkinsFile{home + "/secrets/master.key", jenkinsMasterKey},
		jenkinsFile{home + "/secrets/hudson.util.Secret", string(raw)}
}

func evaluateJenkins(t *testing.T, files ...jenkinsFile) ([]Finding, []credentialanalysis.Candidate) {
	t.Helper()
	engine := newNoiseEngine(t)
	recorder := &recordingCandidateSink{}
	engine.SetCredentialCandidateSink(recorder)
	var findings []Finding
	for _, f := range files {
		name := path.Base(f.path)
		findings = append(findings, engine.Evaluate(FileMetadata{Host: "build01", Share: "D$", FilePath: f.path, Name: name, Extension: path.Ext(name), Size: int64(len(f.content))}, []byte(f.content)).Findings...)
	}
	return findings, recorder.candidates
}

func jenkinsDecrypted(candidates []credentialanalysis.Candidate) map[string]credentialanalysis.Candidate {
	out := map[string]credentialanalysis.Candidate{}
	for _, c := range candidates {
		if c.ValidationBasis == jenkinsDecryptedBasis {
			out[c.Value] = c
		}
	}
	return out
}

// Jenkins credentials decrypt with the home's master.key and
// hudson.util.Secret whichever order the walk meets the three files in.
func TestJenkinsSecretsDecryptInAnyOrder(t *testing.T) {
	credentials, master, hudson := jenkinsHome(t, "ci/jenkins_home")
	for name, order := range map[string][]jenkinsFile{
		"walk order":  {credentials, hudson, master},
		"keys first":  {master, hudson, credentials},
		"interleaved": {hudson, credentials, master},
	} {
		findings, candidates := evaluateJenkins(t, order...)
		got := jenkinsDecrypted(candidates)
		password, ok := got["Tr4in-Jenk-2026!"]
		if !ok || password.Identity != `CORP\svc_build` || password.Verification != credentialanalysis.Confirmed || password.Path != credentials.path {
			t.Errorf("%s: password not decrypted for its account: %+v", name, got)
		}
		if token, ok := got["build-token-SYNTHETIC-8842"]; !ok || token.Identity != "" {
			t.Errorf("%s: secret text not decrypted on its own: %+v", name, token)
		}
		if !actionableRules(findings)[JenkinsSecretsRuleID] {
			t.Errorf("%s: no actionable Jenkins finding: %v", name, findingRuleSet(findings))
		}
	}
}

// Jenkins backups on file shares are usually archives of the whole home.
func TestJenkinsSecretsDecryptInsideAnArchive(t *testing.T) {
	credentials, master, hudson := jenkinsHome(t, "jenkins_home")
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, f := range []jenkinsFile{credentials, master, hudson} {
		member, err := w.Create(f.path)
		if err != nil {
			t.Fatal(err)
		}
		member.Write([]byte(f.content))
	}
	w.Close()
	_, candidates := evaluateJenkins(t, jenkinsFile{"Backups/jenkins-2026-10.zip", buf.String()})
	if _, ok := jenkinsDecrypted(candidates)["Tr4in-Jenk-2026!"]; !ok {
		t.Errorf("Jenkins secrets in a backup archive not decrypted: %+v", jenkinsDecrypted(candidates))
	}
}

// Keys only decrypt the secrets of their own Jenkins home, and a wrong
// master.key decrypts nothing.
func TestJenkinsKeysStayWithTheirHome(t *testing.T) {
	credentials, _, _ := jenkinsHome(t, "ci/home-a")
	_, master, hudson := jenkinsHome(t, "ci/home-b")
	_, candidates := evaluateJenkins(t, credentials, master, hudson)
	if got := jenkinsDecrypted(candidates); len(got) != 0 {
		t.Errorf("another home's key decrypted secrets: %+v", got)
	}

	credentials, master, hudson = jenkinsHome(t, "ci/jenkins_home")
	master.content = strings.Repeat("0", len(jenkinsMasterKey))
	findings, candidates := evaluateJenkins(t, credentials, master, hudson)
	if got := jenkinsDecrypted(candidates); len(got) != 0 {
		t.Errorf("wrong master.key decrypted secrets: %+v", got)
	}
	if findingRuleSet(findings)[JenkinsSecretsRuleID] {
		t.Error("Jenkins finding without decrypted secrets")
	}
}

// Machine keys, VNC and TeamViewer passwords are actionable credentials.
func TestRemoteStoreAndMachineKeyFindingsAreActionable(t *testing.T) {
	webConfig := `<configuration><system.web><machineKey validationKey="` + strings.Repeat("A1B2C3D4E5F60718", 8) + `" decryptionKey="` + strings.Repeat("0F1E2D3C4B5A6978", 2) + `" validation="HMACSHA256" decryption="AES" /></system.web></configuration>`
	ultraVNC := "[ultravnc]\r\npasswd=0B6BFE063F5C12D6AB\r\n"
	for p, content := range map[string]string{
		"inetpub/wwwroot/portal/web.config":   webConfig,
		"Program Files/UltraVNC/ultravnc.ini": ultraVNC,
		"IT/exports/tightvnc.reg":             "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\TightVNC\\Server]\r\n\"Password\"=hex:0b,6b,fe,06,3f,5c,12,d6\r\n",
	} {
		findings, candidates := harvestAt(t, p, content)
		if len(actionableRules(findings)) == 0 {
			t.Errorf("%s: not actionable: %v", p, findingRuleSet(findings))
		}
		confirmed := false
		for _, c := range candidates {
			if c.Verification == credentialanalysis.Confirmed {
				confirmed = true
			}
		}
		if !confirmed {
			t.Errorf("%s: no confirmed credential: %+v", p, candidates)
		}
	}
}
