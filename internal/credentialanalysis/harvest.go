package credentialanalysis

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"snablr/internal/legacyoffice"
	"snablr/internal/textdecode"
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
	candidates, _ := HarvestWithReport(input)
	return candidates
}

// InspectionNote describes a content-inspection limitation for material that was
// read successfully but could not be fully parsed. It carries no credential
// values.
type InspectionNote struct {
	Parser   string
	Category string
	Detail   string
}

// HarvestWithReport runs the shared harvester and additionally reports
// inspection limitations (for example an encrypted legacy document), so callers
// can distinguish "could not read" from "read but could not inspect".
func HarvestWithReport(input HarvestInput) ([]Candidate, []InspectionNote) {
	report := &harvestReport{}
	candidates := harvest(input, report)
	return candidates, report.notes
}

type harvestReport struct {
	notes []InspectionNote
}

func (r *harvestReport) note(note InspectionNote) {
	if r == nil || note.Category == "" {
		return
	}
	r.notes = append(r.notes, note)
}

func harvest(input HarvestInput, report *harvestReport) []Candidate {
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
	ext := strings.ToLower(filepath.Ext(input.Path))
	// Legacy OLE/CFB Office documents are binary containers: their visible text
	// is recovered structurally and then fed through the same semantic layer and
	// table renderer used for modern Office and delimited exports.
	if legacyoffice.IsOLE(content) {
		harvestLegacyOffice(content, add, report)
		return out
	}
	textContent := textdecode.Normalize(content)
	if strings.TrimSpace(textContent) == "" {
		return out
	}
	addPrivateKeyCandidates(textContent, add)
	normalizedContent := []byte(textContent)
	structured := false
	if strings.HasPrefix(strings.TrimSpace(textContent), "{") || strings.HasPrefix(strings.TrimSpace(textContent), "[") {
		if value, err := decodeJSON(normalizedContent); err == nil {
			harvestJSON(value, add)
			structured = true
		}
	}
	if (ext == ".xml" || ext == ".config" || strings.HasPrefix(strings.TrimSpace(textContent), "<")) && strings.Contains(textContent, "<") && strings.Contains(textContent, ">") {
		structured = harvestXML(normalizedContent, add)
		// XML parsing is intentionally attempted before the generic line
		// harvester; well-formed XML has its own object/attribute scope.
	}
	if strings.TrimSpace(textContent) != "" {
		if !structured {
			harvestInlinePairs(textContent, add)
			if ext == ".yaml" || ext == ".yml" {
				if harvestYAML(normalizedContent, add) {
					structured = true
				}
			}
			if structured {
				return out
			}
		}
		if !structured {
			harvestLines(textContent, add)
			// Delimited exports (CSV/TSV) keep their rows as records so that
			// header-mapped credentials correlate per row and never across rows.
			if ext == ".csv" || ext == ".tsv" {
				if rendered := delimitedRecordText(textContent); rendered != "" {
					harvestLines(rendered, add)
				}
			}
		}
	}
	return out
}

// delimitedRecordText renders delimited text as sectioned records using the
// shared table renderer. It returns "" when the text is not a recognizable
// credential table.
func delimitedRecordText(text string) string {
	rows, ok := ParseDelimitedText(text)
	if !ok {
		return ""
	}
	return RenderTableText(rows, "delimited")
}

// harvestLegacyOffice recovers credential material from a legacy OLE/CFB
// Office document (Word 97-2003, Excel 97-2003). Extracted spreadsheet grids and
// tab-separated document tables go through the same shared table renderer, and
// plain document text goes through the same line harvester.
func harvestLegacyOffice(content []byte, add func(Candidate), report *harvestReport) {
	document, ok := legacyoffice.Extract(content)
	if !ok {
		return
	}
	switch document.Status {
	case legacyoffice.StatusEncrypted:
		report.note(InspectionNote{Parser: document.Kind.ParserName(), Category: "encrypted content", Detail: document.Detail()})
		return
	case legacyoffice.StatusMalformed:
		report.note(InspectionNote{Parser: document.Kind.ParserName(), Category: "malformed content", Detail: document.Detail()})
		return
	case legacyoffice.StatusUnsupported:
		report.note(InspectionNote{Parser: document.Kind.ParserName(), Category: "unsupported content", Detail: document.Detail()})
		return
	case legacyoffice.StatusTooLarge:
		report.note(InspectionNote{Parser: document.Kind.ParserName(), Category: "resource/size limit", Detail: document.Detail()})
		return
	}
	if document.Encrypted {
		report.note(InspectionNote{Parser: document.Kind.ParserName(), Category: "encrypted content", Detail: document.Detail()})
		return
	}
	scope := string(document.Kind)
	if scope == "" {
		scope = "legacy office"
	}
	if len(document.Grid) > 0 {
		if rendered := RenderTableText(document.Grid, scope+" spreadsheet"); rendered != "" {
			harvestLines(rendered, add)
			return
		}
		rows := make([]string, 0, len(document.Grid))
		for _, row := range document.Grid {
			rows = append(rows, joinTableRow(row))
		}
		if rendered := RenderTableText(parseRowCells(rows), scope+" spreadsheet"); rendered != "" {
			harvestLines(rendered, add)
			return
		}
	}
	if strings.TrimSpace(document.Text) == "" {
		return
	}
	// Document tables are reconstructed as tab-separated rows; the shared
	// renderer applies header/label semantics, otherwise the text is harvested
	// as ordinary lines.
	if rendered := RenderTableText(parseRowCells(strings.Split(document.Text, "\n")), scope+" document"); rendered != "" {
		harvestLines(rendered, add)
		return
	}
	// Paragraph-form documents are grouped into bounded blocks so a label and its
	// value inside one block correlate, matching the DOCX body behaviour.
	if rendered := renderDocumentBlocks(document.Text, scope+" document"); rendered != "" {
		harvestLines(rendered, add)
		return
	}
	harvestLines(document.Text, add)
}

// renderDocumentBlocks renders reconstructed document text as bounded [scope
// block N] sections. Blank lines delimit blocks and each block is capped so a
// label can never pair with unrelated text far away in the document.
func renderDocumentBlocks(text, scope string) string {
	const maxBlockLines = 12
	var builder strings.Builder
	var block []string
	index := 0
	emit := func(lines []string) {
		if len(lines) == 0 {
			return
		}
		index++
		builder.WriteString("[" + scope + " block " + strconv.Itoa(index) + "]\n")
		for _, line := range lines {
			builder.WriteString(line)
			builder.WriteString("\n")
		}
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			emit(block)
			block = nil
			continue
		}
		block = append(block, line)
		if len(block) >= maxBlockLines {
			emit(block)
			block = nil
		}
	}
	emit(block)
	return builder.String()
}

// parseRowCells splits tab-separated logical rows into a table, dropping rows
// that carry no cells.
func parseRowCells(rows []string) [][]string {
	table := make([][]string, 0, len(rows))
	for _, row := range rows {
		if strings.TrimSpace(row) == "" {
			continue
		}
		table = append(table, strings.Split(row, "\t"))
	}
	return table
}

func joinTableRow(row []string) string {
	return strings.Join(row, "\t")
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
	root, err := parseXMLHarvestTree(content)
	if err != nil || root == nil {
		return false
	}
	walkXMLHarvest(root, add)
	return true
}

type xmlHarvestNode struct {
	name     string
	attrs    map[string]string
	text     string
	parent   *xmlHarvestNode
	children []*xmlHarvestNode
}

func parseXMLHarvestTree(content []byte) (*xmlHarvestNode, error) {
	decoder := xml.NewDecoder(strings.NewReader(string(content)))
	decoder.CharsetReader = func(_ string, reader io.Reader) (io.Reader, error) {
		return reader, nil
	}
	var root *xmlHarvestNode
	var current *xmlHarvestNode
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch item := token.(type) {
		case xml.StartElement:
			node := &xmlHarvestNode{name: item.Name.Local, attrs: make(map[string]string)}
			for _, attr := range item.Attr {
				node.attrs[normalizeKey(attr.Name.Local)] = strings.TrimSpace(attr.Value)
			}
			if current == nil {
				root = node
			} else {
				node.parent = current
				current.children = append(current.children, node)
			}
			current = node
		case xml.EndElement:
			if current != nil {
				current = current.parent
			}
		case xml.CharData:
			if current != nil {
				current.text += string(item)
			}
		}
	}
	if root == nil {
		return nil, io.EOF
	}
	return root, nil
}

func walkXMLHarvest(node *xmlHarvestNode, add func(Candidate)) {
	if node == nil {
		return
	}
	for _, child := range node.children {
		walkXMLHarvest(child, add)
	}
	harvestGenericXMLNode(node, add)
	if isSecretElement(node.name) {
		harvestXMLSecretElement(node, add)
	}
}

func harvestGenericXMLNode(node *xmlHarvestNode, add func(Candidate)) {
	if node == nil {
		return
	}
	fields := make(map[string]string)
	if key := firstNonEmpty(node.attrs["key"], node.attrs["name"]); key != "" {
		if value := firstNonEmpty(node.attrs["value"], node.attrs["text"]); value != "" {
			fields[normalizeKey(key)] = value
		}
	}
	for _, child := range node.children {
		if !strings.EqualFold(child.name, "add") {
			continue
		}
		key := firstNonEmpty(child.attrs["key"], child.attrs["name"])
		value := firstNonEmpty(child.attrs["value"], child.attrs["text"])
		if key != "" && value != "" {
			fields[normalizeKey(key)] = value
		}
	}
	if len(fields) > 0 {
		harvestFields(fields, add, "structured XML object")
	}
}

func harvestXMLSecretElement(node *xmlHarvestNode, add func(Candidate)) {
	value := xmlElementValue(node)
	if strings.TrimSpace(value) == "" {
		return
	}
	identity, domain := xmlCredentialContext(node)
	plainText, hasPlainText := xmlChildValue(node, "plaintext")
	verification := Review
	basis := "windows_unattend_credential_element"
	reasons := []string{"credential-like XML element requires semantic review"}

	switch {
	case strings.EqualFold(node.name, "administratorpassword"):
		if identity == "" {
			identity = "Administrator"
		}
		if hasPlainText && strings.EqualFold(plainText, "true") {
			verification = Confirmed
			basis = "windows_unattend_plaintext_administrator_password"
		} else {
			reasons = append(reasons, "plaintext flag was not positively confirmed")
		}
	case isPasswordKey(node.name):
		// Any element whose terminal token is a password alias behaves like
		// <Password>, including the Norwegian <Passord>.
		switch {
		case hasPlainText && strings.EqualFold(plainText, "false"):
			reasons = append(reasons, "plaintext flag is false")
		case hasPlainText && strings.EqualFold(plainText, "true"):
			if identity != "" {
				verification = Confirmed
				basis = "windows_unattend_plaintext_password"
			}
		case identity != "":
			verification = Confirmed
			basis = "windows_unattend_structured_password"
		}
	}

	if looksReferenceOrTemplate(value) {
		reasons = append(reasons, "value resembles template or variable reference")
	} else if verification == Confirmed {
		reasons = nil
	}
	add(Candidate{
		Verification:    verification,
		CredentialType:  credentialType(node.name),
		Identity:        identity,
		Domain:          domain,
		Value:           value,
		ValidationBasis: basis,
		ReviewReasons:   reasons,
	})
}

func xmlElementValue(node *xmlHarvestNode) string {
	if node == nil {
		return ""
	}
	if value := strings.TrimSpace(node.text); value != "" {
		return value
	}
	if value, ok := node.attrs["value"]; ok && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	if value, ok := xmlChildValue(node, "value"); ok {
		return value
	}
	return ""
}

func xmlChildValue(node *xmlHarvestNode, name string) (string, bool) {
	if node == nil {
		return "", false
	}
	for _, child := range node.children {
		if !strings.EqualFold(child.name, name) && normalizeKey(child.name) != normalizeKey(name) {
			continue
		}
		if value := strings.TrimSpace(child.text); value != "" {
			return value, true
		}
		if value, ok := child.attrs["value"]; ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

func xmlCredentialContext(node *xmlHarvestNode) (string, string) {
	if node == nil {
		return "", ""
	}
	if strings.EqualFold(node.name, "administratorpassword") {
		return "Administrator", xmlContextDomain(node.parent)
	}
	for ancestor := node.parent; ancestor != nil; ancestor = ancestor.parent {
		fields := xmlDirectChildFields(ancestor)
		identity := fieldIdentity(fields)
		domain := fieldDomain(fields)
		if identity != "" || domain != "" {
			return identity, domain
		}
		if strings.EqualFold(ancestor.name, "credentials") || strings.EqualFold(ancestor.name, "autologon") || strings.EqualFold(ancestor.name, "domaincredentials") {
			break
		}
	}
	return "", ""
}

func xmlContextDomain(node *xmlHarvestNode) string {
	for ancestor := node; ancestor != nil; ancestor = ancestor.parent {
		if domain := fieldDomain(xmlDirectChildFields(ancestor)); domain != "" {
			return domain
		}
	}
	return ""
}

func xmlDirectChildFields(node *xmlHarvestNode) map[string]string {
	fields := make(map[string]string)
	if node == nil {
		return fields
	}
	for _, child := range node.children {
		if value := strings.TrimSpace(child.text); value != "" {
			fields[normalizeKey(child.name)] = value
		}
	}
	return fields
}

func isSecretElement(name string) bool {
	return isSecretKey(name)
}

var assignmentPattern = regexp.MustCompile(`(?im)^\s*([A-Za-z][A-Za-z0-9_.-]{0,63})\s*(?:[:=])\s*(?:["']([^"']*)["']|([^#;\r\n]*))\s*$`)
var inlinePairPattern = regexp.MustCompile(`(?is)["']?(username|user|userid|login|account|brukernavn|bruker|kontonavn|konto)["']?\s*[:=]\s*["']([^"']+)["']\s*[,}]\s*["']?(password|passwd|pwd|passord)["']?\s*[:=]\s*["']([^"']+)["']`)

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
	// Natural-language credential expressions ("Passordet er; X") are rewritten
	// into the shared assignment form before any line-based harvesting, so every
	// text-bearing source is covered by one grammar.
	text = NormalizeCredentialExpressions(text)
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
			if field == "username" || field == "user" || field == "password" || field == "passwd" || field == "passord" || field == "secret" || field == "token" {
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
	identity := fieldIdentity(fields)
	domain := fieldDomain(fields)
	strongAPI := (fields["access_key_id"] != "" || fields["access_key"] != "") && (fields["secret_access_key"] != "" || fields["secret_key"] != "")
	strongClient := fields["client_id"] != "" && fields["client_secret"] != ""
	for key, value := range fields {
		if !isSecretKey(key) || value == "" {
			continue
		}
		candidate := Candidate{Verification: Review, CredentialType: credentialType(key), Identity: identity, Domain: domain, Value: value, ReviewReasons: []string{"credential-like value requires semantic review"}}
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
	key = strings.TrimSpace(key)
	runes := []rune(key)
	var builder strings.Builder
	for i, r := range runes {
		switch {
		case unicode.IsUpper(r):
			if i > 0 {
				prev := runes[i-1]
				nextIsLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
				if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextIsLower) {
					builder.WriteByte('_')
				}
			}
			builder.WriteRune(unicode.ToLower(r))
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			builder.WriteRune(unicode.ToLower(r))
		default:
			builder.WriteByte('_')
		}
	}
	key = builder.String()
	key = strings.NewReplacer("-", "_", " ", "_", ".", "_").Replace(key)
	return strings.Trim(key, "_")
}

func isSecretKey(key string) bool {
	key = normalizeKey(key)
	if isPasswordKey(key) {
		return true
	}
	tokens := keyTokens(key)
	if len(tokens) == 0 {
		return false
	}
	last := tokens[len(tokens)-1]
	switch last {
	case "secret", "token":
		if last == "token" && len(tokens) >= 2 && tokens[len(tokens)-2] == "key" {
			return false
		}
		return true
	case "key":
		if len(tokens) < 2 {
			return false
		}
		prefix := tokens[len(tokens)-2]
		return prefix == "api" || prefix == "access" || prefix == "secret"
	default:
		return false
	}
}

func isPasswordKey(key string) bool {
	return ClassifyFieldName(key) == FieldRolePassword
}

func keyTokens(key string) []string {
	normalized := normalizeKey(key)
	if normalized == "" {
		return nil
	}
	parts := strings.FieldsFunc(normalized, func(r rune) bool {
		return r == '_' || r == ' ' || r == '-' || r == '.'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			out = append(out, part)
		}
	}
	return out
}

func fieldIdentity(fields map[string]string) string {
	return SelectFieldValue(fields, FieldRoleIdentity)
}

func fieldDomain(fields map[string]string) string {
	return SelectFieldValue(fields, FieldRoleDomain)
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
