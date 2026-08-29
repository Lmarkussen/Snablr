package credentialanalysis

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const (
	maxHarvestBytes = 8 << 20
	maxHarvestItems = 256
)

// HarvestInput describes already-read content. Harvest is deliberately
// independent of scanner findings and their priority or confidence.
type HarvestInput struct {
	Content   []byte
	Source    string
	Host      string
	Share     string
	Path      string
	Container string
}

// NeedsContent identifies bounded, text-like inputs that should be made
// available to the independent harvester. This affects read eligibility only;
// it never creates a finding from a filename or path.
func NeedsContent(path, name string, size int64) bool {
	ext := strings.ToLower(filepath.Ext(name))
	if ext == "" {
		ext = strings.ToLower(filepath.Ext(path))
	}
	switch ext {
	case ".json", ".yaml", ".yml", ".xml", ".config", ".ini", ".env", ".conf", ".txt", ".md", ".ps1", ".py", ".sh", ".pem", ".key", ".ed25519", ".openssh":
		return true
	case ".jpg", ".jpeg", ".png", ".gif", ".zip", ".7z", ".gz", ".exe", ".dll", ".so", ".pdf", ".wim", ".dit":
		return false
	default:
		// Unknown small files may still contain a private key or a literal
		// credential. The caller applies the scanner's overall size limit.
		return size >= 0 && size <= maxHarvestBytes
	}
}

func Harvest(input HarvestInput) []Candidate {
	content := input.Content
	if len(content) > maxHarvestBytes {
		content = content[:maxHarvestBytes]
	}
	if len(content) == 0 {
		return nil
	}
	base := func(candidate Candidate) Candidate {
		candidate.Source, candidate.Host, candidate.Share = input.Source, input.Host, input.Share
		candidate.Path, candidate.Container = input.Path, input.Container
		candidate.Evidence = []Evidence{{Source: input.Source, Path: input.Path}}
		return candidate
	}
	var out []Candidate
	add := func(candidate Candidate) {
		if len(out) >= maxHarvestItems || strings.TrimSpace(candidate.Value) == "" {
			return
		}
		out = append(out, base(candidate))
	}
	text := string(content)
	ext := strings.ToLower(filepath.Ext(input.Path))
	addPrivateKeyCandidates(text, add)
	structured := false
	textContent := string(content)
	if strings.HasPrefix(strings.TrimSpace(textContent), "{") || strings.HasPrefix(strings.TrimSpace(textContent), "[") {
		if value, err := decodeJSON(content); err == nil {
			harvestJSON(value, add)
			structured = true
		}
	}
	if (ext == ".xml" || ext == ".config" || strings.HasPrefix(strings.TrimSpace(textContent), "<")) && strings.Contains(textContent, "<") && strings.Contains(textContent, ">") {
		structured = harvestXML(content, add)
		// XML parsing is intentionally attempted before the generic line
		// harvester; well-formed XML has its own object/attribute scope.
	}
	if strings.TrimSpace(textContent) != "" {
		if !structured {
			harvestInlinePairs(textContent, add)
			if ext == ".yaml" || ext == ".yml" {
				if harvestYAML(content, add) {
					structured = true
				}
			}
			if structured {
				return out
			}
		}
		if !structured {
			harvestLines(textContent, add)
		}
	}
	return out
}

func decodeJSON(content []byte) (any, error) {
	var value any
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func harvestJSON(value any, add func(Candidate)) {
	switch object := value.(type) {
	case map[string]any:
		fields := make(map[string]string)
		for key, raw := range object {
			if text, ok := raw.(string); ok {
				fields[normalizeKey(key)] = strings.TrimSpace(text)
			}
		}
		harvestFields(fields, add, "structured JSON object")
		for _, raw := range object {
			harvestJSON(raw, add)
		}
	case []any:
		for _, raw := range object {
			harvestJSON(raw, add)
		}
	}
}

func harvestYAML(content []byte, add func(Candidate)) bool {
	var node yaml.Node
	if err := yaml.Unmarshal(content, &node); err != nil {
		return false
	}
	root := &node
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode && root.Kind != yaml.SequenceNode {
		return false
	}
	var walk func(*yaml.Node)
	walk = func(current *yaml.Node) {
		if current == nil {
			return
		}
		if current.Kind == yaml.MappingNode {
			fields := make(map[string]string)
			for i := 0; i+1 < len(current.Content); i += 2 {
				key, value := current.Content[i], current.Content[i+1]
				if value.Kind == yaml.ScalarNode {
					fields[normalizeKey(key.Value)] = strings.TrimSpace(value.Value)
				}
			}
			harvestFields(fields, add, "structured YAML object")
		}
		for _, child := range current.Content {
			walk(child)
		}
	}
	walk(&node)
	return true
}

func harvestXML(content []byte, add func(Candidate)) bool {
	decoder := xml.NewDecoder(strings.NewReader(string(content)))
	stack := []map[string]string{}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return true
		}
		if err != nil {
			return false
		}
		switch item := token.(type) {
		case xml.StartElement:
			fields := map[string]string{}
			for _, attr := range item.Attr {
				fields[normalizeKey(attr.Name.Local)] = strings.TrimSpace(attr.Value)
			}
			if len(stack) > 0 && len(fields) > 0 {
				key := firstNonEmpty(fields["key"], fields["name"])
				value := firstNonEmpty(fields["value"], fields["text"])
				if key != "" && value != "" {
					stack[len(stack)-1][normalizeKey(key)] = value
				}
			}
			stack = append(stack, fields)
		case xml.EndElement:
			if len(stack) == 0 {
				continue
			}
			fields := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if key := firstNonEmpty(fields["key"], fields["name"]); key != "" {
				if value := firstNonEmpty(fields["value"], fields["text"]); value != "" {
					harvestFields(map[string]string{normalizeKey(key): value}, add, "structured XML object")
				}
			}
			harvestFields(fields, add, "structured XML object")
		}
	}
}

var assignmentPattern = regexp.MustCompile(`(?im)^\s*([A-Za-z][A-Za-z0-9_.-]{0,63})\s*(?:[:=])\s*(?:["']([^"']*)["']|([^#;\r\n]*))\s*$`)
var inlinePairPattern = regexp.MustCompile(`(?is)["']?(username|user|userid|login|account)["']?\s*[:=]\s*["']([^"']+)["']\s*[,}]\s*["']?(password|passwd|pwd)["']?\s*[:=]\s*["']([^"']+)["']`)

func harvestInlinePairs(text string, add func(Candidate)) {
	for _, match := range inlinePairPattern.FindAllStringSubmatch(text, -1) {
		if looksReferenceOrTemplate(match[4]) {
			add(Candidate{Verification: Review, CredentialType: "password", Identity: match[2], Value: match[4], ReviewReasons: []string{"value resembles template or variable reference"}})
			continue
		}
		add(Candidate{Verification: Confirmed, CredentialType: "password", Identity: match[2], Value: match[4], ValidationBasis: "structured credential object"})
	}
}

func harvestLines(text string, add func(Candidate)) {
	sections := map[string]map[string]string{"": {}}
	section := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if sections[section] == nil {
				sections[section] = map[string]string{}
			}
			continue
		}
		match := assignmentPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		key, value := normalizeKey(match[1]), strings.TrimSpace(firstNonEmpty(match[2], match[3]))
		if value == "" {
			continue
		}
		sections[section][key] = value
		if strings.Contains(key, "connection") && strings.Contains(strings.ToLower(value), "password") {
			add(Candidate{Verification: Confirmed, CredentialType: "connection_string", Value: value, ValidationBasis: "structured_connection_string"})
		}
	}
	for section, fields := range sections {
		if section != "" {
			harvestFields(fields, add, "structured configuration section")
		}
	}
	// Top-level assignments are deliberately independent. This prevents a
	// username at the start of a large document from being paired with a
	// distant password. Environment-style prefixes provide their own scope.
	prefixes := map[string]map[string]string{}
	for key, value := range sections[""] {
		if isSecretKey(key) {
			candidate := Candidate{Verification: Review, CredentialType: credentialType(key), Value: value, ReviewReasons: []string{"credential-like value requires semantic review"}}
			if looksReferenceOrTemplate(value) {
				candidate.ReviewReasons = append(candidate.ReviewReasons, "value resembles template or variable reference")
			}
			add(candidate)
		}
		if idx := strings.LastIndex(key, "_"); idx > 0 {
			prefix := key[:idx]
			field := key[idx+1:]
			if field == "username" || field == "user" || field == "password" || field == "passwd" || field == "secret" || field == "token" {
				if prefixes[prefix] == nil {
					prefixes[prefix] = map[string]string{}
				}
				prefixes[prefix][field] = value
			}
		}
	}
	for _, fields := range prefixes {
		harvestFields(fields, add, "structured environment record")
	}
}

func harvestFields(fields map[string]string, add func(Candidate), basis string) {
	if len(fields) == 0 {
		return
	}
	identity := firstNonEmpty(fields["username"], fields["user"], fields["userid"], fields["login"], fields["account"], fields["email"])
	strongAPI := (fields["access_key_id"] != "" || fields["access_key"] != "") && (fields["secret_access_key"] != "" || fields["secret_key"] != "")
	strongClient := fields["client_id"] != "" && fields["client_secret"] != ""
	for key, value := range fields {
		if !isSecretKey(key) || value == "" {
			continue
		}
		candidate := Candidate{Verification: Review, CredentialType: credentialType(key), Identity: identity, Value: value, ReviewReasons: []string{"credential-like value requires semantic review"}}
		if (identity != "" && isPasswordKey(key) || strongAPI || strongClient) && !looksReferenceOrTemplate(value) {
			candidate.Verification = Confirmed
			candidate.ValidationBasis = basis
			candidate.ReviewReasons = nil
		}
		if looksReferenceOrTemplate(value) {
			candidate.ReviewReasons = append(candidate.ReviewReasons, "value resembles template or variable reference")
		}
		add(candidate)
	}
}

func addPrivateKeyCandidates(text string, add func(Candidate)) {
	original := text
	parsedBlock := false
	for {
		rawBlock := ""
		if start := strings.Index(text, "-----BEGIN "); start >= 0 {
			if end := strings.Index(text[start:], "-----END "); end >= 0 {
				footerStart := start + end
				if lineEnd := strings.Index(text[footerStart+len("-----END "):], "-----"); lineEnd >= 0 {
					blockEnd := footerStart + len("-----END ") + lineEnd + len("-----")
					if strings.HasPrefix(text[blockEnd:], "\r\n") {
						blockEnd += 2
					} else if strings.HasPrefix(text[blockEnd:], "\n") {
						blockEnd++
					}
					rawBlock = text[start:blockEnd]
				}
			}
		}
		block, rest := pem.Decode([]byte(text))
		if block == nil {
			break
		}
		parsedBlock = true
		text = string(rest)
		if !strings.Contains(block.Type, "PRIVATE KEY") {
			continue
		}
		valid := false
		if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			valid = true
		} else if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			valid = true
		}
		if strings.EqualFold(block.Type, "OPENSSH PRIVATE KEY") {
			if _, err := ssh.ParseRawPrivateKey(pem.EncodeToMemory(block)); err == nil {
				valid = true
			}
		}
		if strings.EqualFold(block.Type, "ENCRYPTED PRIVATE KEY") {
			// Recognize the encrypted envelope without attempting decryption.
			valid = true
		}
		if valid {
			if rawBlock == "" {
				rawBlock = string(pem.EncodeToMemory(block))
			}
			add(Candidate{Verification: Confirmed, CredentialType: "private_key", Value: rawBlock, Encrypted: strings.EqualFold(block.Type, "ENCRYPTED PRIVATE KEY") || block.Headers["Proc-Type"] != "", ValidationBasis: "parsed_private_key"})
		} else {
			add(Candidate{Verification: Review, CredentialType: "private_key", Value: block.Type, ReviewReasons: []string{"private-key structure was not successfully parsed"}})
		}
	}
	if !parsedBlock && strings.Contains(original, "PRIVATE KEY") {
		add(Candidate{Verification: Review, CredentialType: "private_key", Value: "PRIVATE KEY", ReviewReasons: []string{"private-key-looking block could not be parsed"}})
	}
}

func normalizeKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.NewReplacer("-", "_", " ", "_", ".", "_").Replace(key)
	return key
}

func isSecretKey(key string) bool {
	key = normalizeKey(key)
	return isPasswordKey(key) || strings.Contains(key, "secret") || strings.Contains(key, "token") || strings.Contains(key, "api_key") || strings.Contains(key, "access_key")
}

func isPasswordKey(key string) bool {
	key = normalizeKey(key)
	return key == "password" || key == "passwd" || key == "pwd" || strings.HasSuffix(key, "_password") || strings.HasSuffix(key, "_passwd")
}

func credentialType(key string) string {
	key = normalizeKey(key)
	switch key {
	case "api_key", "apikey":
		return "api_key"
	case "api_secret":
		return "api_secret"
	case "access_key", "access_key_id":
		return "access_key"
	case "secret_key", "secret_access_key":
		return "secret_key"
	case "client_secret":
		return "client_secret"
	case "bearer_token":
		return "bearer_token"
	case "token", "access_token":
		return "token"
	case "secret":
		return "secret"
	}
	return "password"
}

func looksReferenceOrTemplate(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return lower == "null" || lower == "false" || lower == "********" || lower == "<password>" || strings.Contains(lower, "${") || strings.Contains(lower, "{{") || strings.Contains(lower, "%password%") || strings.Contains(lower, "replace_me") || strings.Contains(lower, "your_password") || strings.Contains(lower, "changeme") || lower == "example"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
