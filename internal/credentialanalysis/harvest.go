package credentialanalysis

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"html"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"snablr/internal/legacyoffice"
	"snablr/internal/textdecode"
)

var htmlTagPattern = regexp.MustCompile(`(?is)<[^>]+>`)
var htmlTableRowPattern = regexp.MustCompile(`(?i)</tr\s*>`)
var htmlTableCellPattern = regexp.MustCompile(`(?i)</t[dh]\s*>`)
var htmlTableCellOpenPattern = regexp.MustCompile(`(?i)<t[dh]\b[^>]*>`)
var htmlFormPattern = regexp.MustCompile(`(?is)<form\b[^>]*>(.*?)</form\s*>`)
var htmlInputPattern = regexp.MustCompile(`(?is)<input\b([^>]*)>`)
var htmlAttributePattern = regexp.MustCompile(`(?is)([a-z][a-z0-9_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
var powerShellHashtablePattern = regexp.MustCompile(`(?is)@\{(.*?)\}`)

func htmlCredentialText(content string) string {
	content = htmlTableRowPattern.ReplaceAllString(content, "\n")
	content = htmlTableCellPattern.ReplaceAllString(content, ",")
	content = htmlTableCellOpenPattern.ReplaceAllString(content, "")
	content = htmlTagPattern.ReplaceAllString(content, "\n")
	content = html.UnescapeString(content)
	content = strings.ReplaceAll(content, "\r", "")
	lines := strings.Split(content, "\n")
	compact := make([]string, 0, len(lines))
	for _, line := range lines {
		if line = strings.TrimSpace(line); line != "" {
			compact = append(compact, line)
		}
	}
	return strings.Join(compact, "\n")
}

func markdownTableText(content string) string {
	rows := make([][]string, 0)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		separator := true
		for _, cell := range cells {
			if strings.Trim(cell, "-:") != "" {
				separator = false
				break
			}
		}
		if !separator {
			rows = append(rows, cells)
		}
	}
	if len(rows) < 2 {
		return ""
	}
	return RenderTableText(rows, "markdown")
}

func harvestHTMLForms(content string, add func(Candidate)) {
	for _, form := range htmlFormPattern.FindAllStringSubmatch(content, -1) {
		fields := make(map[string]string)
		for _, input := range htmlInputPattern.FindAllStringSubmatch(form[1], -1) {
			attrs := make(map[string]string)
			for _, attribute := range htmlAttributePattern.FindAllStringSubmatch(input[1], -1) {
				value := attribute[2]
				if value == "" {
					value = attribute[3]
				}
				attrs[strings.ToLower(attribute[1])] = html.UnescapeString(strings.TrimSpace(value))
			}
			name := normalizeKey(attrs["name"])
			value := strings.TrimSpace(attrs["value"])
			if name == "" || value == "" {
				continue
			}
			fields[name] = value
		}
		if len(fields) > 0 {
			harvestFields(fields, add, "structured HTML form")
		}
	}
}

func harvestPowerShellHashtables(content string, add func(Candidate)) {
	for _, match := range powerShellHashtablePattern.FindAllStringSubmatch(content, -1) {
		body := strings.ReplaceAll(match[1], ";", "\n")
		if strings.TrimSpace(body) != "" {
			harvestLines(body, add)
		}
	}
}

const (
	maxHarvestBytes = 8 << 20
	maxHarvestItems = 256
)

// HarvestInput describes already-read content. Harvest is deliberately
// independent of scanner findings and their priority or confidence.
type HarvestInput struct {
	Content         []byte
	Source          string
	Host            string
	Share           string
	Path            string
	Container       string
	SkipPrivateKeys bool
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
	case ".json", ".yaml", ".yml", ".xml", ".config", ".ini", ".env", ".conf", ".toml", ".properties", ".props", ".txt", ".md", ".markdown", ".csv", ".tsv", ".html", ".htm", ".bat", ".cmd", ".ps1", ".py", ".sh", ".pem", ".key", ".ed25519", ".openssh":
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
		if len(candidate.Evidence) == 1 && candidate.Evidence[0].Source == "" && candidate.Evidence[0].Path == "" {
			candidate.Evidence[0].Source = input.Source
			candidate.Evidence[0].Path = input.Path
		} else {
			candidate.Evidence = mergeEvidence(candidate.Evidence, []Evidence{{Source: input.Source, Path: input.Path}})
		}
		return candidate
	}
	var out []Candidate
	add := func(candidate Candidate) {
		if len(out) >= maxHarvestItems || strings.TrimSpace(candidate.Value) == "" {
			return
		}
		// Recognised placeholders and templates are not credential material and
		// are excluded from every credential output, never reported for review.
		if IsPlaceholderValue(candidate.Value) {
			return
		}
		// Scalar secret values must have a scalar secret shape. Syntactically
		// valid assignments whose right-hand side is a SQL variable, function
		// call, schema/metadata definition or a prose fragment are not secrets,
		// regardless of how credential-like the field label is.
		if IsScalarCredentialType(candidate.CredentialType) && candidate.ValidationBasis != "explicit command invocation" {
			if _, reject := NonSecretValueShape(candidate.Value); reject {
				return
			}
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
	if ext == ".html" || ext == ".htm" {
		harvestHTMLForms(textContent, add)
		textContent = htmlCredentialText(textContent)
		if rendered := delimitedRecordText(textContent); rendered != "" {
			textContent = rendered
		}
	} else if ext == ".md" || ext == ".markdown" {
		if rendered := markdownTableText(textContent); rendered != "" {
			textContent = rendered
		}
	}
	harvestPowerShellHashtables(textContent, add)
	if strings.TrimSpace(textContent) == "" {
		return out
	}
	if !input.SkipPrivateKeys {
		addPrivateKeyCandidates(textContent, add)
	}
	normalizedContent := []byte(textContent)
	structured := false
	if strings.HasPrefix(strings.TrimSpace(textContent), "{") || strings.HasPrefix(strings.TrimSpace(textContent), "[") {
		if value, err := decodeJSON(normalizedContent); err == nil {
			// A localization / UI resource bundle maps message identifiers onto
			// human-readable strings. Those strings routinely mention passwords,
			// logins and secrets in prose ("the password is incorrect"), so no
			// credential may be inferred from the bundle structure itself.
			if isLocalizationResource(value) {
				return out
			}
			harvestJSON(value, add)
			structured = true
		}
	}
	if (ext == ".xml" || ext == ".config" || strings.HasPrefix(strings.TrimSpace(textContent), "<")) && strings.Contains(textContent, "<") && strings.Contains(textContent, ">") {
		structured = harvestXML(normalizedContent, add)
		// XML parsing is intentionally attempted before the generic line
		// harvester; well-formed XML has its own object/attribute scope.
	}
	if ext == ".toml" || ext == ".properties" || ext == ".props" {
		harvestStructuredAssignments(textContent, add, ext == ".toml")
		return out
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

// harvestStructuredAssignments handles formats whose credential scope is not
// safely represented by the generic line harvester. TOML table headers and
// Java-properties namespaces delimit independent records; keeping those
// boundaries prevents a username in one object from pairing with a password
// in another object.
func harvestStructuredAssignments(text string, add func(Candidate), toml bool) {
	flush := func(fields map[string]string) {
		if len(fields) != 0 {
			harvestFields(fields, add, "structured configuration scope")
		}
	}
	fields := make(map[string]string)
	propertyScopes := make(map[string]map[string]string)
	flushProperties := func() {
		for _, scoped := range propertyScopes {
			flush(scoped)
		}
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if toml {
				flush(fields)
				fields = make(map[string]string)
			} else {
				flushProperties()
				propertyScopes = make(map[string]map[string]string)
			}
			continue
		}
		match := assignmentPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		rawKey := strings.TrimSpace(match[1])
		key := normalizeKey(rawKey)
		value := strings.TrimSpace(firstNonEmpty(match[2], match[3]))
		if value == "" {
			continue
		}
		if !toml {
			scope := ""
			if dot := strings.LastIndex(rawKey, "."); dot > 0 {
				scope, key = normalizeKey(rawKey[:dot]), normalizeKey(rawKey[dot+1:])
			}
			if propertyScopes[scope] == nil {
				propertyScopes[scope] = make(map[string]string)
			}
			propertyScopes[scope][key] = value
			continue
		}
		fields[key] = value
	}
	if toml {
		flush(fields)
	} else {
		flushProperties()
	}
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

// isLocalizationResource reports whether a decoded JSON document is a
// localization or UI resource bundle rather than data. Such bundles map message
// identifiers onto human-readable strings and their prose routinely mentions
// passwords and logins, so no credential may be inferred from the bundle
// structure. Detection is structural: either the document carries gloss/comment
// entries next to message keys, or its string values are predominantly
// multi-word prose.
func isLocalizationResource(value any) bool {
	var entries [][2]string
	collectStringEntries(value, &entries)
	if len(entries) == 0 {
		return false
	}
	hasComment := false
	prose := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry[0], "comment") {
			hasComment = true
		}
		if looksProseString(entry[1]) {
			prose++
		}
	}
	total := len(entries)
	if hasComment && total >= 2 {
		return true
	}
	return total >= 3 && prose*2 >= total
}

func collectStringEntries(value any, out *[][2]string) {
	switch object := value.(type) {
	case map[string]any:
		for key, raw := range object {
			if text, ok := raw.(string); ok {
				*out = append(*out, [2]string{normalizeKey(key), strings.TrimSpace(text)})
				continue
			}
			collectStringEntries(raw, out)
		}
	case []any:
		for _, raw := range object {
			collectStringEntries(raw, out)
		}
	}
}

// looksProseString reports whether a scalar is natural-language text (two or
// more word-like tokens) rather than a single opaque value.
func looksProseString(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len([]rune(trimmed)) < 4 {
		return false
	}
	words := 0
	for _, field := range strings.Fields(trimmed) {
		if containsLetter(field) {
			words++
		}
	}
	return words >= 2
}

func containsLetter(value string) bool {
	for _, r := range value {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
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
	harvestSCCMXMLScope(node, add)
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
	for key, value := range node.attrs {
		if ClassifyFieldName(key) == FieldRoleIdentity || isPasswordKey(key) || key == "domain" {
			fields[key] = value
		}
	}
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
		harvestFieldsMode(fields, add, "structured XML object", true)
	}
}

func harvestXMLSecretElement(node *xmlHarvestNode, add func(Candidate)) {
	value := xmlElementValue(node)
	if strings.TrimSpace(value) == "" {
		return
	}
	// A token/secret/key element must carry token evidence in its own value.
	// Merely existing as an element named <Token>/<Secret>/<ApiKey> is not
	// enough: application caches and generated metadata contain countless
	// elements with those names whose values are identifiers, timestamps or
	// structured fragments. Password elements keep their own value semantics.
	if !isPasswordKey(node.name) {
		if _, ok := TokenSecretValueShape(value); !ok {
			return
		}
	}
	identity, domain := xmlCredentialContext(node)
	plainText, hasPlainText := xmlChildValue(node, "plaintext")
	identityPlaceholder := IsPlaceholderIdentity(identity)
	verification := Review
	basis := "windows_unattend_credential_element"
	reasons := []string{"credential-like XML element requires semantic review"}

	switch {
	case strings.EqualFold(node.name, "administratorpassword"):
		if identity == "" {
			identity = "Administrator"
			identityPlaceholder = false
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
			if identity != "" && !identityPlaceholder {
				verification = Confirmed
				basis = "windows_unattend_plaintext_password"
			}
		case identity != "" && !identityPlaceholder:
			verification = Confirmed
			basis = "windows_unattend_structured_password"
		}
	}

	if identityPlaceholder {
		reasons = append(reasons, "identity resembles template or variable reference")
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

var assignmentPattern = regexp.MustCompile(`(?im)^\s*([\p{L}][\p{L}\p{N}_. -]{0,63})\s*(?:[:=])\s*(?:["']([^"']*)["']|([^#;\r\n]*))\s*$`)
var inlinePairPattern = regexp.MustCompile(`(?is)["']?(username|user|userid|login|account|brukernavn|bruker|kontonavn|konto)["']?\s*[:=]\s*["']([^"']+)["']\s*[,}]\s*["']?(password|passwd|pwd|passord)["']?\s*[:=]\s*["']([^"']+)["']`)

func harvestInlinePairs(text string, add func(Candidate)) {
	for _, match := range inlinePairPattern.FindAllStringSubmatch(text, -1) {
		identity, value := decodeInlineValue(match[2]), decodeInlineValue(match[4])
		if IsPlaceholderValue(value) {
			// A placeholder is not credential material; it is not routed to
			// review either.
			continue
		}
		if IsPlaceholderIdentity(identity) {
			add(Candidate{Verification: Review, CredentialType: "password", Identity: identity, Value: value, ReviewReasons: []string{"identity resembles template or variable reference"}})
			continue
		}
		add(Candidate{Verification: Confirmed, CredentialType: "password", Identity: identity, Value: value, ValidationBasis: "structured credential object"})
	}
}

func decodeInlineValue(value string) string {
	value = strings.TrimSpace(value)
	if decoded, err := strconv.Unquote(`"` + value + `"`); err == nil {
		return decoded
	}
	return value
}

func harvestLines(text string, add func(Candidate)) {
	// Natural-language credential expressions ("Passordet er; X") are rewritten
	// into the shared assignment form before any line-based harvesting, so every
	// text-bearing source is covered by one grammar.
	text = NormalizeCredentialExpressions(text)
	harvestCommandPairs(text, add)
	sections := map[string]map[string]string{"": {}}
	section := ""
	pairedTopLevelPasswords := make(map[string]struct{})
	var previousTopLevel *struct{ key, value string }
	for index, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, ";") {
			previousTopLevel = nil
			continue
		}
		if harvestNetNTLMRecord(line, index+1, add) {
			continue
		}
		if harvestCaptureRecord(line, index+1, add) {
			continue
		}
		if harvestCanonicalNTHashRecord(line, index+1, add) {
			continue
		}
		line = normalizeAssignmentLine(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			previousTopLevel = nil
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if sections[section] == nil {
				sections[section] = map[string]string{}
			}
			continue
		}
		match := assignmentPattern.FindStringSubmatch(line)
		if match == nil {
			previousTopLevel = nil
			continue
		}
		key, value := normalizeKey(match[1]), strings.TrimSpace(firstNonEmpty(match[2], match[3]))
		if value == "" {
			previousTopLevel = nil
			continue
		}
		sections[section][key] = value
		if section == "" {
			current := &struct{ key, value string }{key: key, value: value}
			_, sccmPasswordField := sccmPasswordAccounts[key]
			if previousTopLevel != nil && ClassifyFieldName(previousTopLevel.key) == FieldRoleIdentity && isPasswordKey(key) && compatibleAssignmentScope(previousTopLevel.key, key) && !sccmPasswordField && !looksReferenceOrTemplate(value) {
				identity := strings.TrimSpace(previousTopLevel.value)
				if identity != "" && !IsPlaceholderIdentity(identity) {
					add(Candidate{Verification: Confirmed, CredentialType: "password", Identity: identity, Value: value, ValidationBasis: "explicit adjacent credential fields"})
					pairedTopLevelPasswords[key] = struct{}{}
				}
			}
			previousTopLevel = current
		}
		if strings.Contains(key, "connection") && strings.Contains(strings.ToLower(value), "password") {
			add(Candidate{Verification: Confirmed, CredentialType: "connection_string", Value: value, ValidationBasis: "structured_connection_string"})
		}
	}
	for section, fields := range sections {
		basis := "structured configuration section"
		if section == "" {
			basis = "structured configuration record"
			harvestNTHashFields(fields, add, basis)
			harvestSCCMFields(fields, add, "structured SCCM configuration record")
		}
		if section != "" {
			harvestScopedFields(fields, add, basis)
		}
	}
	// Top-level assignments are deliberately independent. This prevents a
	// username at the start of a large document from being paired with a
	// distant password. Environment-style prefixes provide their own scope.
	prefixes := map[string]map[string]string{}
	for key, value := range sections[""] {
		if _, sccmField := sccmPasswordAccounts[key]; sccmField {
			continue
		}
		if isSecretKey(key) {
			if _, paired := pairedTopLevelPasswords[key]; paired {
				continue
			}
			candidate := Candidate{Verification: Review, CredentialType: credentialType(key), Value: value, ReviewReasons: []string{"credential-like value requires semantic review"}}
			if looksReferenceOrTemplate(value) {
				candidate.ReviewReasons = append(candidate.ReviewReasons, "value resembles template or variable reference")
			}
			add(candidate)
		}
		if idx := strings.LastIndex(key, "_"); idx > 0 {
			prefix := key[:idx]
			field := key[idx+1:]
			if field == "username" || field == "user" || field == "password" || field == "passwd" || field == "passord" || field == "pass" || field == "secret" || field == "token" {
				if prefixes[prefix] == nil {
					prefixes[prefix] = map[string]string{}
				}
				if field == "pass" {
					field = "password"
				}
				prefixes[prefix][field] = value
			}
		}
	}
	for _, fields := range prefixes {
		harvestFields(fields, add, "structured environment record")
	}
}

func harvestScopedFields(fields map[string]string, add func(Candidate), basis string) {
	scopes := make(map[string]map[string]string)
	for key, value := range fields {
		scope := ""
		field := key
		switch key {
		case "user_id":
			scope, field = "user", "userid"
		case "account_name":
			scope, field = "account", "username"
		}
		for _, suffix := range []string{"username", "userid", "user", "account", "password", "passwd", "pwd", "passord", "secret", "token", "domain"} {
			if scope != "" {
				break
			}
			marker := "_" + suffix
			if strings.HasSuffix(key, marker) && len(key) > len(marker) {
				scope = strings.TrimSuffix(key, marker)
				field = suffix
				break
			}
		}
		if scope != "" && field == "id" {
			field = "userid"
		}
		if scopes[scope] == nil {
			scopes[scope] = make(map[string]string)
		}
		scopes[scope][field] = value
	}
	// Office renderers wrap each logical record in a synthetic section. A
	// record such as account=alice plus user_password=Secret then produces an
	// unscoped identity and a user-scoped password even though both fields came
	// from the same bounded record. Merge that one unscoped identity scope only
	// when there is exactly one explicit companion scope and the fields form an
	// identity/password pair. Multiple explicit scopes remain isolated.
	if base, ok := scopes[""]; ok && len(scopes) == 2 {
		for scope, scoped := range scopes {
			if scope == "" || !hasFieldRole(base, FieldRoleIdentity) || !hasFieldRole(scoped, FieldRolePassword) {
				continue
			}
			for key, value := range base {
				if _, exists := scoped[key]; !exists {
					scoped[key] = value
				}
			}
			break
		}
	}
	for _, scoped := range scopes {
		harvestFields(scoped, add, basis)
	}
}

func hasFieldRole(fields map[string]string, role FieldRole) bool {
	for key := range fields {
		if ClassifyFieldName(key) == role {
			return true
		}
	}
	return false
}

func compatibleAssignmentScope(identityKey, passwordKey string) bool {
	identityScope := assignmentScope(identityKey, []string{"username", "userid", "user", "user_id", "login", "account", "account_name", "service_user", "brukernavn", "bruker", "brukerkonto", "påloggingsnavn", "uid"})
	passwordScope := assignmentScope(passwordKey, []string{"password", "passwd", "pwd", "pass", "passord", "account_password", "user_password"})
	return identityScope == "" || passwordScope == "" || identityScope == passwordScope
}

func assignmentScope(key string, suffixes []string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, suffix := range suffixes {
		for _, separator := range []string{"_", ".", "-"} {
			if strings.HasSuffix(key, separator+suffix) {
				return strings.TrimSuffix(key, separator+suffix)
			}
		}
		if key == suffix {
			return ""
		}
	}
	return key
}

func harvestCommandPairs(text string, add func(Candidate)) {
	lines := strings.Split(text, "\n")
	for index := 0; index < len(lines); index++ {
		line := strings.TrimSpace(lines[index])
		for (strings.HasSuffix(line, "\\") || strings.HasSuffix(line, "^")) && index+1 < len(lines) {
			line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(line, "\\"), "^")) + " " + strings.TrimSpace(lines[index+1])
			index++
		}
		if line == "" {
			continue
		}
		tokens := commandTokens(line)
		var identities, passwords []string
		for tokenIndex := 0; tokenIndex < len(tokens); tokenIndex++ {
			token := tokens[tokenIndex]
			lower := strings.ToLower(token)
			role, inlineValue := commandSwitch(lower, token)
			if role == "" {
				continue
			}
			value := inlineValue
			if value == "" && tokenIndex+1 < len(tokens) {
				value = tokens[tokenIndex+1]
				tokenIndex++
			}
			value = strings.TrimSpace(value)
			if value == "" || looksReferenceOrTemplate(value) || looksCommandPlaceholder(value) {
				continue
			}
			if role == "identity" {
				identities = appendUniqueCommandValue(identities, value)
			} else {
				passwords = appendUniqueCommandValue(passwords, value)
			}
		}
		if len(identities) != 1 || len(passwords) != 1 || IsPlaceholderIdentity(identities[0]) || IsPlaceholderValue(passwords[0]) || looksCommandPlaceholder(identities[0]) || looksCommandPlaceholder(passwords[0]) {
			continue
		}
		add(Candidate{Verification: Confirmed, CredentialType: "password", Identity: identities[0], Value: passwords[0], ValidationBasis: "explicit command invocation"})
	}
}

func looksCommandPlaceholder(value string) bool {
	switch strings.ToLower(strings.TrimSpace(strings.Trim(value, "<>[]{}"))) {
	case "user", "username", "account", "password", "passwd", "pwd", "pass", "value", "your-user", "your-password":
		return true
	default:
		return strings.HasPrefix(strings.TrimSpace(value), "<") && strings.HasSuffix(strings.TrimSpace(value), ">")
	}
}

func appendUniqueCommandValue(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func commandSwitch(lower, original string) (string, string) {
	for _, item := range []struct {
		role string
		keys []string
	}{
		{role: "identity", keys: []string{"--username", "--user", "-username", "-user", "-u", "/username", "/user"}},
		{role: "password", keys: []string{"--password", "--passwd", "--pass", "-password", "-passwd", "-pass", "-p", "/password", "/passwd", "/pass"}},
	} {
		for _, key := range item.keys {
			if lower == key {
				return item.role, ""
			}
			if strings.HasPrefix(lower, key+"=") {
				return item.role, original[len(key)+1:]
			}
			if strings.HasPrefix(lower, key+":") {
				return item.role, original[len(key)+1:]
			}
		}
	}
	return "", ""
}

func commandTokens(line string) []string {
	var tokens []string
	var builder strings.Builder
	quote := rune(0)
	flush := func() {
		if builder.Len() > 0 {
			tokens = append(tokens, builder.String())
			builder.Reset()
		}
	}
	for _, character := range line {
		if quote != 0 {
			if character == quote {
				quote = 0
			} else {
				builder.WriteRune(character)
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			continue
		}
		if unicode.IsSpace(character) {
			flush()
			continue
		}
		builder.WriteRune(character)
	}
	flush()
	return tokens
}

// normalizeAssignmentLine strips bounded shell/PowerShell assignment prefixes
// before the shared assignment parser runs. It deliberately only removes
// syntax, not semantic vocabulary: export/set prefixes and a leading "$" are
// common in script files already selected for content inspection.
func normalizeAssignmentLine(line string) string {
	line = strings.TrimSpace(line)
	lower := strings.ToLower(line)
	switch {
	case strings.HasPrefix(lower, "export "):
		return strings.TrimSpace(line[len("export "):])
	case strings.HasPrefix(lower, "set "):
		assignment := strings.TrimSpace(line[len("set "):])
		if len(assignment) >= 2 && assignment[0] == '"' && assignment[len(assignment)-1] == '"' {
			assignment = strings.TrimSpace(assignment[1 : len(assignment)-1])
		}
		return assignment
	case strings.HasPrefix(line, "$"):
		return strings.TrimSpace(line[1:])
	default:
		return line
	}
}

func harvestFields(fields map[string]string, add func(Candidate), basis string) {
	harvestFieldsMode(fields, add, basis, false)
}

// harvestFieldsMode classifies a set of same-scope key/value fields. When
// requireTokenShape is set every token/secret/API-key field must carry a
// token-shaped value; this is used for structured XML where a credential-like
// element or key name is otherwise the only evidence available.
func harvestFieldsMode(fields map[string]string, add func(Candidate), basis string, requireTokenShape bool) {
	if len(fields) == 0 {
		return
	}
	if basis != "structured XML object" {
		harvestSCCMFields(fields, add, basis)
	}
	identity := fieldIdentity(fields)
	domain := fieldDomain(fields)
	identityKey := fieldIdentityKey(fields)
	harvestNTHashFields(fields, add, basis)
	// A prose/label fragment or SQL expression cannot be an account identity
	// either; drop it so a real password value is not confirmed against a bogus
	// identity.
	if _, reject := NonSecretValueShape(identity); reject {
		identity = ""
	}
	// A symbolic/template identity ("USER_TEMPLATE", "%APP_USER%") is not an
	// account, so an identity + password field pairing must not confirm the
	// password on the strength of that identity alone.
	identityPlaceholder := IsPlaceholderIdentity(identity)
	strongAPI := (fields["access_key_id"] != "" || fields["access_key"] != "") && (fields["secret_access_key"] != "" || fields["secret_key"] != "")
	strongClient := fields["client_id"] != "" && fields["client_secret"] != ""
	for key, value := range fields {
		if _, sccmField := sccmPasswordAccounts[key]; sccmField {
			continue
		}
		if !isSecretKey(key) || value == "" {
			continue
		}
		credType := credentialType(key)
		explicitAccountSecret := normalizeKey(key) == "secret" && identityKey == "account"
		if requireTokenShape && !isPasswordKey(key) {
			if _, ok := TokenSecretValueShape(value); !ok {
				continue
			}
		}
		candidate := Candidate{Verification: Review, CredentialType: credType, Identity: identity, Domain: domain, Value: value, ReviewReasons: []string{"credential-like value requires semantic review"}}
		if (identity != "" && !identityPlaceholder && (isPasswordKey(key) || explicitAccountSecret) && compatibleAssignmentScope(identityKey, key) || strongAPI || strongClient) && !looksReferenceOrTemplate(value) {
			candidate.Verification = Confirmed
			candidate.ValidationBasis = basis
			candidate.ReviewReasons = nil
		}
		if identityPlaceholder {
			candidate.ReviewReasons = append(candidate.ReviewReasons, "identity resembles template or variable reference")
		}
		if looksReferenceOrTemplate(value) {
			candidate.ReviewReasons = append(candidate.ReviewReasons, "value resembles template or variable reference")
		}
		add(candidate)
	}
}

var ntHashFieldNames = map[string]struct{}{
	"nt_hash":   {},
	"nthash":    {},
	"ntlm_hash": {},
}

var lmDisabledSentinels = map[string]struct{}{
	"aad3b435b51404eeaad3b435b51404ee": {},
}

func harvestCanonicalNTHashRecord(line string, lineNumber int, add func(Candidate)) bool {
	fields := strings.Split(line, ":")
	if len(fields) != 4 {
		return false
	}
	rid, err := strconv.ParseUint(strings.TrimSpace(fields[1]), 10, 32)
	if err != nil {
		return true
	}
	identity := strings.TrimSpace(fields[0])
	lmHash := strings.ToLower(strings.TrimSpace(fields[2]))
	ntHash := strings.ToLower(strings.TrimSpace(fields[3]))
	if !meaningfulHashIdentity(identity) || !validHexHash(lmHash) || !validHexHash(ntHash) {
		return true
	}
	if _, ok := lmDisabledSentinels[lmHash]; !ok {
		return true
	}
	account, domain := splitQualifiedIdentity(identity)
	candidate := Candidate{
		Verification:    Confirmed,
		CredentialType:  "nt_hash",
		Identity:        account,
		Domain:          domain,
		Value:           ntHash,
		RID:             uint32(rid),
		ValidationBasis: "structured_nt_hash_record",
		Evidence:        []Evidence{{Location: "line " + strconv.Itoa(lineNumber)}},
	}
	add(candidate)
	return true
}

func harvestNTHashFields(fields map[string]string, add func(Candidate), basis string) {
	if len(fields) == 0 {
		return
	}
	identity := fieldIdentity(fields)
	if !meaningfulHashIdentity(identity) {
		return
	}
	for key, value := range fields {
		if _, ok := ntHashFieldNames[normalizeKey(key)]; !ok || !validHexHash(value) {
			continue
		}
		account, domain := splitQualifiedIdentity(identity)
		candidate := Candidate{
			Verification:    Confirmed,
			CredentialType:  "nt_hash",
			Identity:        account,
			Domain:          domain,
			Value:           strings.ToLower(strings.TrimSpace(value)),
			ValidationBasis: basis,
		}
		if ridText := strings.TrimSpace(fields["rid"]); ridText != "" {
			if rid, err := strconv.ParseUint(ridText, 10, 32); err == nil {
				candidate.RID = uint32(rid)
			}
		}
		add(candidate)
	}
}

func meaningfulHashIdentity(identity string) bool {
	identity = strings.TrimSpace(identity)
	return identity != "" && !IsPlaceholderIdentity(identity) && !strings.ContainsAny(identity, "\r\n\t")
}

func validHexHash(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 32 {
		return false
	}
	for _, r := range value {
		if !isHexRune(r) {
			return false
		}
	}
	return true
}

func splitQualifiedIdentity(identity string) (string, string) {
	identity = strings.TrimSpace(identity)
	if index := strings.LastIndex(identity, `\`); index > 0 && index < len(identity)-1 {
		return identity[index+1:], identity[:index]
	}
	if index := strings.LastIndex(identity, "@"); index > 0 && index < len(identity)-1 {
		return identity[:index], identity[index+1:]
	}
	return identity, ""
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
	for index, token := range tokens {
		if token == "password" || token == "passwd" || token == "pwd" || token == "passord" {
			if index+1 < len(tokens) {
				suffix := tokens[index+1]
				if suffix != "only" && suffix != "value" && suffix != "secret" {
					continue
				}
			}
			return true
		}
	}
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

func fieldIdentityKey(fields map[string]string) string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		if ClassifyFieldName(key) == FieldRoleIdentity {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
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
	switch {
	case strings.HasSuffix(key, "_token"):
		return "token"
	case strings.HasSuffix(key, "_secret"):
		return "secret"
	case strings.HasSuffix(key, "_api_key"):
		return "api_key"
	}
	return "password"
}

// looksReferenceOrTemplate reports whether a value is a placeholder, template or
// variable reference rather than a literal secret. It delegates to the shared
// structural placeholder classifier so every harvest path sees the same rules.
func looksReferenceOrTemplate(value string) bool {
	return IsPlaceholderValue(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
