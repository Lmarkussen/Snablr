package scanner

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"

	"snablr/internal/credentialanalysis"
	"snablr/internal/jenkinsinspect"
	"snablr/internal/rules"
)

// A Jenkins home keeps its encrypted secrets (credentials.xml, job and node
// config.xml) and the key that decrypts them (secrets/master.key and
// secrets/hudson.util.Secret) in separate files. The walk meets them in any
// order, so the correlator remembers both sides per Jenkins home and
// decrypts as soon as a home's key and its secrets are known.

const JenkinsSecretsRuleID = "jenkinsinspect.secrets_decrypted"

const jenkinsDecryptedBasis = "Jenkins secret decrypted with the controller's master key"

var jenkinsSecretsRule = rules.Rule{
	ID:          JenkinsSecretsRuleID,
	Name:        "Jenkins Secrets Decrypted",
	Description: "Jenkins credentials were decrypted offline with the controller's master.key and hudson.util.Secret.",
	Type:        rules.RuleTypeContent,
	Severity:    rules.SeverityCritical,
	Confidence:  rules.ConfidenceHigh,
	Category:    "credentials",
	Tags:        []string{"credentials", "jenkins", "confirmed"},
	Explanation: "A Jenkins home stores its credentials encrypted with a key kept in the same home. Anyone who can read secrets/master.key, secrets/hudson.util.Secret and the configuration files recovers every stored credential.",
	Remediation: "Restrict access to the Jenkins home and its backups, rotate every credential stored in Jenkins, and generate new master.key and hudson.util.Secret files.",
}

// jenkinsMaxPending bounds the encrypted values kept while their home's key
// is not known yet.
const jenkinsMaxPending = 20000

type jenkinsPending struct {
	meta   FileMetadata
	secret jenkinsinspect.Secret
}

type jenkinsCorrelator struct {
	mu        sync.Mutex
	masterKey map[string][]byte // home -> secrets/master.key
	hudson    map[string][]byte // home -> secrets/hudson.util.Secret
	keys      map[string][]byte // home -> secret key
	pending   map[string][]jenkinsPending
	count     int
}

func newJenkinsCorrelator() *jenkinsCorrelator {
	return &jenkinsCorrelator{
		masterKey: map[string][]byte{},
		hudson:    map[string][]byte{},
		keys:      map[string][]byte{},
		pending:   map[string][]jenkinsPending{},
	}
}

// jenkinsKeyFile reports whether a path is one of a Jenkins home's key files
// and returns the home's correlation key.
func jenkinsKeyFile(meta FileMetadata) (home string, master bool, ok bool) {
	filePath := strings.ToLower(strings.ReplaceAll(meta.FilePath, `\`, "/"))
	dir, name := path.Split(filePath)
	dir = strings.TrimSuffix(dir, "/")
	if path.Base(dir) != "secrets" && !strings.HasSuffix(dir, "!secrets") {
		return "", false, false
	}
	switch name {
	case "master.key":
		master = true
	case "hudson.util.secret":
	default:
		return "", false, false
	}
	return jenkinsScope(meta, strings.TrimSuffix(strings.TrimSuffix(dir, "secrets"), "/")), master, true
}

// insideJenkinsHome reports whether a lower-case file path lies in a home
// directory: "" is the share root, "backup.zip!" the root of an archive.
func insideJenkinsHome(filePath, home string) bool {
	switch {
	case home == "":
		return true
	case strings.HasSuffix(home, "!"):
		return strings.HasPrefix(filePath, home)
	default:
		return strings.HasPrefix(filePath, home+"/") || strings.HasPrefix(filePath, home+"!")
	}
}

func jenkinsScope(meta FileMetadata, home string) string {
	return strings.ToLower(meta.Host) + "\x00" + strings.ToLower(meta.Share) + "\x00" + home
}

// homeFor returns the known Jenkins home that holds the file, the longest
// matching one when homes are nested.
func (c *jenkinsCorrelator) homeFor(meta FileMetadata) (string, []byte) {
	filePath := strings.ToLower(strings.ReplaceAll(meta.FilePath, `\`, "/"))
	best, bestKey := "", []byte(nil)
	for home, key := range c.keys {
		prefix := strings.ToLower(meta.Host) + "\x00" + strings.ToLower(meta.Share) + "\x00"
		if !strings.HasPrefix(home, prefix) {
			continue
		}
		if !insideJenkinsHome(filePath, strings.TrimPrefix(home, prefix)) {
			continue
		}
		if bestKey == nil || len(home) > len(best) {
			best, bestKey = home, key
		}
	}
	return best, bestKey
}

// observe takes a file's content and returns the credentials it allowed to
// decrypt: its own secrets when its home's key is known, or every pending
// secret of the home whose key it completes.
func (c *jenkinsCorrelator) observe(meta FileMetadata, content []byte) []credentialanalysis.Candidate {
	if c == nil || len(content) == 0 {
		return nil
	}
	if home, master, ok := jenkinsKeyFile(meta); ok {
		return c.observeKeyFile(home, master, content)
	}
	if !jenkinsSecretSource(meta, content) {
		return nil
	}
	secrets := jenkinsinspect.Secrets(content)
	if len(secrets) == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, key := c.homeFor(meta); key != nil {
		return decryptJenkinsSecrets(key, pendingFor(meta, secrets))
	}
	scope := jenkinsScope(meta, "")
	for _, secret := range secrets {
		if c.count >= jenkinsMaxPending {
			break
		}
		c.pending[scope] = append(c.pending[scope], jenkinsPending{meta: meta, secret: secret})
		c.count++
	}
	return nil
}

func (c *jenkinsCorrelator) observeKeyFile(home string, master bool, content []byte) []credentialanalysis.Candidate {
	c.mu.Lock()
	defer c.mu.Unlock()
	if master {
		c.masterKey[home] = append([]byte(nil), content...)
	} else {
		c.hudson[home] = append([]byte(nil), content...)
	}
	if _, done := c.keys[home]; done || c.masterKey[home] == nil || c.hudson[home] == nil {
		return nil
	}
	key, ok := jenkinsinspect.SecretKey(c.masterKey[home], c.hudson[home])
	if !ok {
		return nil
	}
	c.keys[home] = key
	// Decrypt the pending secrets of files inside this home.
	parts := strings.SplitN(home, "\x00", 3)
	scope := parts[0] + "\x00" + parts[1] + "\x00"
	dir := parts[2]
	var inside, outside []jenkinsPending
	for _, item := range c.pending[scope] {
		filePath := strings.ToLower(strings.ReplaceAll(item.meta.FilePath, `\`, "/"))
		if insideJenkinsHome(filePath, dir) {
			inside = append(inside, item)
		} else {
			outside = append(outside, item)
		}
	}
	c.pending[scope] = outside
	c.count -= len(inside)
	return decryptJenkinsSecrets(key, inside)
}

// jenkinsSecretSource reports files that can hold Jenkins secrets: XML whose
// content carries the current encrypted form, or Jenkins' own files.
func jenkinsSecretSource(meta FileMetadata, content []byte) bool {
	name := strings.ToLower(meta.Name)
	if !strings.HasSuffix(name, ".xml") {
		return false
	}
	text := string(content)
	return strings.Contains(text, "{AQAAAB") || name == "credentials.xml"
}

func pendingFor(meta FileMetadata, secrets []jenkinsinspect.Secret) []jenkinsPending {
	out := make([]jenkinsPending, 0, len(secrets))
	for _, secret := range secrets {
		out = append(out, jenkinsPending{meta: meta, secret: secret})
	}
	return out
}

func decryptJenkinsSecrets(key []byte, items []jenkinsPending) []credentialanalysis.Candidate {
	var out []credentialanalysis.Candidate
	for _, item := range items {
		plaintext, ok := jenkinsinspect.Decrypt(key, item.secret.Value)
		if !ok || strings.TrimSpace(plaintext) == "" {
			continue
		}
		candidate := credentialanalysis.Candidate{
			Verification:    credentialanalysis.Confirmed,
			CredentialType:  jenkinsCredentialType(item.secret.Field, plaintext),
			Identity:        strings.TrimSpace(item.secret.Username),
			Value:           plaintext,
			Source:          item.meta.Source,
			Host:            item.meta.Host,
			Share:           item.meta.Share,
			Path:            item.meta.FilePath,
			Container:       item.meta.ArchivePath,
			ValidationBasis: jenkinsDecryptedBasis,
			Evidence: []credentialanalysis.Evidence{{
				RuleID:   JenkinsSecretsRuleID,
				Source:   item.meta.Source,
				Path:     item.meta.FilePath,
				Location: jenkinsLocation(item.secret),
			}},
		}
		out = append(out, candidate)
	}
	return out
}

func jenkinsCredentialType(field, plaintext string) string {
	switch strings.ToLower(field) {
	case "privatekey":
		if strings.Contains(plaintext, "PRIVATE KEY") {
			return "private_key"
		}
		return "secret"
	case "password", "passphrase", "privatekeypassword", "secretpassphrase":
		return "password"
	case "apitoken", "token":
		return "token"
	default:
		return "secret"
	}
}

func jenkinsLocation(secret jenkinsinspect.Secret) string {
	location := "<" + secret.Field + ">"
	if secret.CredentialID != "" {
		location += " of credential " + secret.CredentialID
	}
	return location
}

// jenkinsFinding reports decrypted Jenkins credentials on the file whose
// evaluation decrypted them.
func jenkinsFinding(meta FileMetadata, decrypted []credentialanalysis.Candidate) Finding {
	files := map[string]struct{}{}
	account := ""
	for _, candidate := range decrypted {
		files[candidate.Path] = struct{}{}
		if account == "" {
			account = candidate.Identity
		}
	}
	names := make([]string, 0, len(files))
	for file := range files {
		names = append(names, file)
	}
	sort.Strings(names)
	match := fmt.Sprintf("decrypted %d Jenkins secret(s) from %s", len(decrypted), strings.Join(names, ", "))
	return newFinding(jenkinsSecretsRule, meta, findingEvidence{
		SignalType:          "validated",
		Match:               match,
		MatchedText:         match,
		MatchedTextRedacted: match,
		PotentialAccount:    account,
	})
}

// recordJenkinsSecrets decrypts what this file allows, records the
// credentials and returns the finding to report on this file.
func (e *Engine) recordJenkinsSecrets(meta FileMetadata, content []byte) []Finding {
	decrypted := e.jenkins.observe(meta, content)
	if len(decrypted) == 0 {
		return nil
	}
	if e.candidateSink != nil {
		for _, candidate := range decrypted {
			candidate = reviewIfThirdPartyLibrary(candidate)
			if err := e.candidateSink.RecordCredentialCandidate(candidate); err != nil && e.log != nil {
				e.log.Errorf("Jenkins credential recording failed for %s: %v", candidate.Path, err)
			}
		}
	}
	return []Finding{jenkinsFinding(meta, decrypted)}
}
