package output

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

type CredsWriter struct {
	closer     io.Closer
	findings   []scanner.Finding
	ntds       map[string]ntdsCredentialEntry
	candidates []credentialanalysis.Candidate
	mu         sync.Mutex
	w          io.Writer
}

type ntdsCredentialEntry struct {
	domain, account, source, sid, hash string
	rid                                uint32
	machine, disabled                  bool
}

type credentialEntry struct {
	Group    string
	SortKey  string
	DedupKey string
	Paths    []string
	Fields   []credentialField
}

type credentialField struct {
	Label string
	Value string
}

func NewCredsWriter(w io.Writer, closer io.Closer) *CredsWriter {
	return &CredsWriter{
		w:      w,
		closer: closer,
		ntds:   make(map[string]ntdsCredentialEntry),
	}
}

// ExportNTDSCurrentHash is the explicit highly-sensitive NTDS export path.
// The raw bytes are converted immediately and are never attached to a
// Finding or any persisted scan metadata.
func (c *CredsWriter) ExportNTDSCurrentHash(domain, account, source string, rid uint32, sid string, machine, disabled bool, hash []byte) error {
	if len(hash) != 16 {
		return fmt.Errorf("NTDS current hash must be 16 bytes")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := ntdsCredentialEntry{domain: strings.TrimSpace(domain), account: strings.TrimSpace(account), source: strings.TrimSpace(source), sid: strings.TrimSpace(sid), rid: rid, machine: machine, disabled: disabled, hash: hex.EncodeToString(hash)}
	key := strings.ToLower(entry.domain) + "\x00" + strings.ToLower(entry.account) + fmt.Sprintf("\x00%d\x00%s\x00%s\x00%s", entry.rid, entry.sid, entry.source, entry.hash)
	c.ntds[key] = entry
	c.candidates = append(c.candidates, credentialanalysis.Candidate{Verification: credentialanalysis.Confirmed, CredentialType: "nt_hash", Identity: entry.account, Domain: entry.domain, Value: entry.hash, RID: entry.rid, SID: entry.sid, AccountType: accountType(entry.machine), Disabled: entry.disabled, Source: entry.source, ValidationBasis: "cryptographic_ntds_recovery"})
	return nil
}

func accountType(machine bool) string {
	if machine {
		return "machine"
	}
	return "user"
}

func (c *CredsWriter) RecordCredentialCandidate(candidate credentialanalysis.Candidate) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.candidates = append(c.candidates, candidate)
	if candidate.Verification == credentialanalysis.Confirmed && strings.EqualFold(candidate.CredentialType, "nt_hash") {
		hash, err := hex.DecodeString(strings.TrimSpace(candidate.Value))
		if err != nil || len(hash) != 16 {
			return fmt.Errorf("invalid NTDS candidate hash")
		}
		entry := ntdsCredentialEntry{domain: strings.TrimSpace(candidate.Domain), account: strings.TrimSpace(candidate.Identity), source: strings.TrimSpace(candidate.Source), sid: strings.TrimSpace(candidate.SID), rid: candidate.RID, machine: strings.EqualFold(candidate.AccountType, "machine"), disabled: candidate.Disabled, hash: strings.ToLower(hex.EncodeToString(hash))}
		key := strings.ToLower(entry.domain) + "\x00" + strings.ToLower(entry.account) + fmt.Sprintf("\x00%d\x00%s\x00%s\x00%s", entry.rid, entry.sid, entry.source, entry.hash)
		c.ntds[key] = entry
	}
	return nil
}

func (c *CredsWriter) WriteFinding(f scanner.Finding) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.findings = append(c.findings, f)
	return nil
}

func (c *CredsWriter) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries := buildCredentialEntries(augmentFindingsForReporting(c.findings))
	analysis := analyzeCandidates(c.findings, c.candidates)
	ntdsEntries := make([]ntdsCredentialEntry, 0, len(c.ntds))
	for _, entry := range c.ntds {
		ntdsEntries = append(ntdsEntries, entry)
	}
	sort.Slice(ntdsEntries, func(i, j int) bool {
		left := strings.ToLower(ntdsEntries[i].domain + "\x00" + ntdsEntries[i].account + fmt.Sprintf("\x00%d\x00%s\x00%s", ntdsEntries[i].rid, ntdsEntries[i].source, ntdsEntries[i].hash))
		right := strings.ToLower(ntdsEntries[j].domain + "\x00" + ntdsEntries[j].account + fmt.Sprintf("\x00%d\x00%s\x00%s", ntdsEntries[j].rid, ntdsEntries[j].source, ntdsEntries[j].hash))
		return left < right
	})
	if len(entries) == 0 && len(ntdsEntries) == 0 && len(analysis.Confirmed) == 0 && len(analysis.Review) == 0 {
		if _, err := io.WriteString(c.w, "# No high-confidence credentials were exported.\n"); err != nil {
			if c.closer != nil {
				_ = c.closer.Close()
			}
			return err
		}
		if c.closer == nil {
			return nil
		}
		return c.closer.Close()
	}

	groupOrder := []string{
		"AWS Credentials",
		"Database Credentials",
		"Application / Deployment Credentials",
		"Application Secrets",
		"API Tokens",
		"SSH Private Keys",
	}
	groupIndex := make(map[string]int, len(groupOrder))
	for idx, group := range groupOrder {
		groupIndex[group] = idx
	}

	sort.SliceStable(entries, func(i, j int) bool {
		leftIdx, leftOK := groupIndex[entries[i].Group]
		rightIdx, rightOK := groupIndex[entries[j].Group]
		switch {
		case leftOK && rightOK && leftIdx != rightIdx:
			return leftIdx < rightIdx
		case leftOK != rightOK:
			return leftOK
		case entries[i].Group != entries[j].Group:
			return entries[i].Group < entries[j].Group
		default:
			return entries[i].SortKey < entries[j].SortKey
		}
	})

	var builder strings.Builder
	if len(analysis.Confirmed) > 0 {
		builder.WriteString("==== CONFIRMED CREDENTIALS ====\n")
		builder.WriteString(fmt.Sprintf("Count: %d\n\n", len(analysis.Confirmed)))
	}
	// Legacy curated sections remain useful for established formats. Mark the
	// shared records they render by source path, then render every other
	// confirmed candidate generically. This keeps the sensitive export a
	// complete projection of the shared analysis model rather than a partial
	// view of only legacy credential families.
	renderedConfirmed := make(map[string]struct{})
	for _, candidate := range analysis.Candidates {
		if candidate.Verification != credentialanalysis.Confirmed {
			continue
		}
		for _, entry := range entries {
			if entry.Group == "SSH Private Keys" && strings.EqualFold(candidate.CredentialType, "private_key") {
				if !hasRawPrivateCandidateAtPath(analysis.Candidates, entry.Paths) && candidatePathMatches(candidate, entry.Paths) {
					renderedConfirmed[candidateExportKey(candidate)] = struct{}{}
				}
				continue
			}
			if candidatePathMatches(candidate, entry.Paths) {
				renderedConfirmed[candidateExportKey(candidate)] = struct{}{}
				break
			}
		}
		if strings.EqualFold(candidate.CredentialType, "private_key") && !isRawPrivateCandidate(candidate) {
			for _, entry := range entries {
				if entry.Group == "SSH Private Keys" && candidatePathMatches(candidate, entry.Paths) {
					renderedConfirmed[candidateExportKey(candidate)] = struct{}{}
					break
				}
			}
		}
		for _, entry := range ntdsEntries {
			if candidate.Path == entry.source || candidate.Source == entry.source {
				renderedConfirmed[candidateExportKey(candidate)] = struct{}{}
				break
			}
		}
	}
	currentGroup := ""
	for _, entry := range entries {
		if entry.Group == "SSH Private Keys" && hasRawPrivateCandidateAtPath(analysis.Candidates, entry.Paths) {
			continue
		}
		if entry.Group != currentGroup {
			if builder.Len() > 0 {
				builder.WriteString("\n")
			}
			builder.WriteString("==== " + entry.Group + " ====\n")
			currentGroup = entry.Group
		}
		if len(entry.Paths) == 1 {
			builder.WriteString("Path: " + entry.Paths[0] + "\n")
		} else {
			builder.WriteString("Paths:\n")
			for _, path := range entry.Paths {
				builder.WriteString("- " + path + "\n")
			}
		}
		for _, field := range entry.Fields {
			builder.WriteString(field.Label + ": " + field.Value + "\n")
		}
		builder.WriteString("\n")
	}
	if len(ntdsEntries) > 0 {
		if builder.Len() > 0 {
			builder.WriteString("\n")
		}
		builder.WriteString("==== NTDS Current NT Hashes ====\n")
		for _, entry := range ntdsEntries {
			builder.WriteString("Source: " + entry.source + "\n")
			if entry.domain != "" {
				builder.WriteString("Domain: " + entry.domain + "\n")
			}
			builder.WriteString("Account: " + entry.account + "\n")
			builder.WriteString(fmt.Sprintf("RID: %d\n", entry.rid))
			if entry.sid != "" {
				builder.WriteString("SID: " + entry.sid + "\n")
			}
			kind := "user"
			if entry.machine {
				kind = "machine"
			}
			builder.WriteString("Account type: " + kind + "\n")
			builder.WriteString(fmt.Sprintf("Disabled: %t\n", entry.disabled))
			builder.WriteString("Current NT hash: " + entry.hash + "\n\n")
		}
	}
	for _, candidate := range analysis.Candidates {
		if candidate.Verification != credentialanalysis.Confirmed {
			continue
		}
		if strings.EqualFold(candidate.CredentialType, "private_key") && !isRawPrivateCandidate(candidate) && hasLegacyPrivateEntry(candidate, entries) {
			continue
		}
		if _, ok := renderedConfirmed[candidateExportKey(candidate)]; ok {
			continue
		}
		if builder.Len() > 0 {
			builder.WriteString("\n")
		}
		builder.WriteString("==== Confirmed Credential Material ====\n")
		builder.WriteString("Type: " + candidate.CredentialType + "\n")
		if candidate.Encrypted {
			builder.WriteString("Encrypted: yes\n")
		}
		if candidate.Domain != "" {
			builder.WriteString("Domain: " + candidate.Domain + "\n")
		}
		if candidate.Identity != "" {
			builder.WriteString("Identity: " + candidate.Identity + "\n")
		}
		builder.WriteString("Value: " + candidate.Value + "\n")
		writeCandidateProvenance(&builder, candidate)
		builder.WriteString("Validation: " + candidate.ValidationBasis + "\n\n")
	}
	if len(analysis.Review) > 0 {
		if builder.Len() > 0 {
			builder.WriteString("\n")
		}
		builder.WriteString("==== POTENTIAL CREDENTIAL MATERIAL — REVIEW ====\n")
		builder.WriteString(fmt.Sprintf("Count: %d\n\n", len(analysis.Review)))
		for _, candidate := range analysis.Candidates {
			if candidate.Verification != credentialanalysis.Review {
				continue
			}
			builder.WriteString("Type: " + candidate.CredentialType + "\n")
			if candidate.Identity != "" {
				builder.WriteString("Identity candidate: " + candidate.Identity + "\n")
			}
			if candidate.Encrypted {
				builder.WriteString("Encrypted: yes\n")
			}
			builder.WriteString("Value: " + candidate.Value + "\n")
			writeCandidateProvenance(&builder, candidate)
			builder.WriteString("Review reason: " + strings.Join(candidate.ReviewReasons, "; ") + "\n\n")
		}
	}

	if _, err := io.WriteString(c.w, strings.TrimRight(builder.String(), "\n")+"\n"); err != nil {
		if c.closer != nil {
			_ = c.closer.Close()
		}
		return err
	}
	if c.closer == nil {
		return nil
	}
	return c.closer.Close()
}

func hasLegacyPrivateEntry(candidate credentialanalysis.Candidate, entries []credentialEntry) bool {
	for _, entry := range entries {
		if entry.Group == "SSH Private Keys" && candidatePathMatches(candidate, entry.Paths) {
			return true
		}
	}
	return false
}

func hasRawPrivateCandidateAtPath(candidates []credentialanalysis.Candidate, paths []string) bool {
	for _, candidate := range candidates {
		if candidate.Verification == credentialanalysis.Confirmed && isRawPrivateCandidate(candidate) && candidatePathMatches(candidate, paths) {
			return true
		}
	}
	return false
}

func isRawPrivateCandidate(candidate credentialanalysis.Candidate) bool {
	return strings.EqualFold(candidate.CredentialType, "private_key") && strings.HasPrefix(strings.TrimSpace(candidate.Value), "-----BEGIN ")
}

func candidateExportKey(candidate credentialanalysis.Candidate) string {
	return strings.ToLower(strings.TrimSpace(candidate.CredentialType)) + "\x00" +
		strings.ToLower(strings.TrimSpace(candidate.Domain)) + "\x00" +
		strings.ToLower(strings.TrimSpace(candidate.Identity)) + "\x00" + candidate.Value
}

func candidatePathMatches(candidate credentialanalysis.Candidate, paths []string) bool {
	for _, path := range paths {
		if path == candidate.Path || path == candidate.Source {
			return true
		}
		for _, evidence := range candidate.Evidence {
			if evidence.Path == path {
				return true
			}
		}
	}
	return false
}

func hasConfirmedCandidateAtPath(candidates []credentialanalysis.Candidate, paths []string, credentialType string) bool {
	for _, candidate := range candidates {
		if candidate.Verification != credentialanalysis.Confirmed || !strings.EqualFold(candidate.CredentialType, credentialType) {
			continue
		}
		if candidatePathMatches(candidate, paths) {
			return true
		}
	}
	return false
}

func writeCandidateProvenance(builder *strings.Builder, candidate credentialanalysis.Candidate) {
	primary := strings.TrimSpace(candidate.Source)
	if candidate.Path != "" && (primary == "" || primary == "cli") {
		primary = candidate.Path
	}
	if primary != "" {
		builder.WriteString("Source: " + primary + "\n")
	}
	seen := map[string]struct{}{candidate.Path: {}, candidate.Source: {}}
	additional := make([]string, 0, len(candidate.Evidence))
	for _, evidence := range candidate.Evidence {
		path := strings.TrimSpace(evidence.Path)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		additional = append(additional, path)
	}
	sort.Strings(additional)
	if len(additional) == 0 {
		return
	}
	const maxAdditional = 8
	builder.WriteString("Also observed:\n")
	for _, path := range additional[:minInt(len(additional), maxAdditional)] {
		builder.WriteString("- " + path + "\n")
	}
	if len(additional) > maxAdditional {
		builder.WriteString(fmt.Sprintf("Additional sources: %d more\n", len(additional)-maxAdditional))
	}
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func buildCredentialEntries(findings []scanner.Finding) []credentialEntry {
	deduped := make(map[string]credentialEntry)
	for _, finding := range findings {
		entry, ok := credentialEntryFromFinding(finding)
		if !ok {
			continue
		}
		existing, exists := deduped[entry.DedupKey]
		if !exists {
			entry.Paths = uniqueSorted(entry.Paths)
			deduped[entry.DedupKey] = entry
			continue
		}
		existing.Paths = uniqueSorted(append(existing.Paths, entry.Paths...))
		deduped[entry.DedupKey] = existing
	}

	entries := make([]credentialEntry, 0, len(deduped))
	for _, entry := range deduped {
		entries = append(entries, entry)
	}
	return entries
}

func credentialEntryFromFinding(f scanner.Finding) (credentialEntry, bool) {
	if !isExportableCredentialFinding(f) {
		return credentialEntry{}, false
	}

	switch strings.ToLower(strings.TrimSpace(f.RuleID)) {
	case "awsinspect.content.credentials_bundle":
		return awsCredentialEntry(f)
	case "dbinspect.access.connection_string", "dbinspect.access.dsn":
		return databaseCredentialEntry(f)
	case "keyinspect.content.private_key_header":
		return privateKeyEntry(f)
	case "content.password_assignment_indicators",
		"content.password_note_value_indicators",
		"content.note_style_credential_pair_indicators",
		"content.secret_assignment_indicators",
		"content.unattended_deployment_password_fields":
		return genericCredentialEntry(f)
	default:
		return credentialEntry{}, false
	}
}

func isExportableCredentialFinding(f scanner.Finding) bool {
	if !isPrimaryLiveFinding(f) {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(f.TriageClass), "weak-review") || strings.EqualFold(strings.TrimSpace(f.TriageClass), "config-only") {
		return false
	}
	if !hasExportableConfidence(f) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(f.RuleID)) {
	case "awsinspect.content.credentials_bundle",
		"dbinspect.access.connection_string",
		"dbinspect.access.dsn",
		"keyinspect.content.private_key_header",
		"content.password_assignment_indicators",
		"content.password_note_value_indicators",
		"content.note_style_credential_pair_indicators",
		"content.secret_assignment_indicators",
		"content.unattended_deployment_password_fields":
		return true
	default:
		return false
	}
}

func hasExportableConfidence(f scanner.Finding) bool {
	if confidenceRankForExport(f.Confidence) >= 3 {
		return true
	}
	return f.ConfidenceScore >= 60
}

func confidenceRankForExport(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func awsCredentialEntry(f scanner.Finding) (credentialEntry, bool) {
	values := parseAssignmentValues(joinNonEmpty(f.MatchedText, f.Context))
	accessKey := firstNonEmpty(values["aws_access_key_id"], values["aws_access_key"])
	secretKey := values["aws_secret_access_key"]
	sessionToken := values["aws_session_token"]
	if accessKey == "" || secretKey == "" {
		return credentialEntry{}, false
	}
	if looksPlaceholderCredential(accessKey) || looksPlaceholderCredential(secretKey) || looksPlaceholderCredential(sessionToken) {
		return credentialEntry{}, false
	}
	fields := []credentialField{
		{Label: "AccessKey", Value: accessKey},
		{Label: "SecretKey", Value: secretKey},
	}
	if sessionToken != "" {
		fields = append(fields, credentialField{Label: "SessionToken", Value: sessionToken})
	}
	profile := awsProfileName(f)
	if profile != "" {
		fields = append(fields, credentialField{Label: "Profile", Value: profile})
	}
	dedup := "aws::" + accessKey + "::" + secretKey + "::" + sessionToken
	return credentialEntry{
		Group:    "AWS Credentials",
		SortKey:  exportSourcePath(f),
		DedupKey: dedup,
		Paths:    []string{exportSourcePath(f)},
		Fields:   fields,
	}, true
}

func databaseCredentialEntry(f scanner.Finding) (credentialEntry, bool) {
	raw := firstNonEmpty(strings.TrimSpace(f.MatchedText), strings.TrimSpace(f.Context))
	if raw == "" {
		return credentialEntry{}, false
	}
	info := parseDatabaseCredential(raw)
	if info.password == "" || looksPlaceholderCredential(info.password) {
		return credentialEntry{}, false
	}
	fields := []credentialField{}
	if info.host != "" {
		fields = append(fields, credentialField{Label: "Host", Value: info.host})
	}
	if info.database != "" {
		fields = append(fields, credentialField{Label: "Database", Value: info.database})
	}
	if info.user != "" {
		fields = append(fields, credentialField{Label: "User", Value: info.user})
	}
	fields = append(fields, credentialField{Label: "Password", Value: info.password})
	if info.raw != "" {
		fields = append(fields, credentialField{Label: "Connection", Value: info.raw})
	}
	dedup := "db::" + info.host + "::" + info.database + "::" + info.user + "::" + info.password + "::" + info.raw
	return credentialEntry{
		Group:    "Database Credentials",
		SortKey:  exportSourcePath(f),
		DedupKey: dedup,
		Paths:    []string{exportSourcePath(f)},
		Fields:   fields,
	}, true
}

func privateKeyEntry(f scanner.Finding) (credentialEntry, bool) {
	keyType := strings.TrimSpace(f.Match)
	if keyType == "" {
		keyType = strings.TrimSpace(f.MatchedText)
	}
	if keyType == "" {
		return credentialEntry{}, false
	}
	fields := []credentialField{{Label: "Type", Value: keyType}}
	fingerprint := strings.TrimSpace(firstNonEmpty(f.Context, f.MatchedText, f.FilePath))
	return credentialEntry{
		Group:    "SSH Private Keys",
		SortKey:  exportSourcePath(f),
		DedupKey: "ssh-key::" + fingerprint,
		Paths:    []string{exportSourcePath(f)},
		Fields:   fields,
	}, true
}

func genericCredentialEntry(f scanner.Finding) (credentialEntry, bool) {
	values := parseAssignmentValues(joinNonEmpty(f.Context, f.MatchedText))
	secretLabel, secretValue := bestSecretValue(values)
	if secretValue == "" || looksPlaceholderCredential(secretValue) {
		return credentialEntry{}, false
	}

	group := "Application / Deployment Credentials"
	switch {
	case strings.Contains(secretLabel, "token"):
		group = "API Tokens"
	case strings.Contains(secretLabel, "secret"), strings.Contains(secretLabel, "api_key"), strings.Contains(secretLabel, "client_key"):
		group = "Application Secrets"
	}

	fields := []credentialField{}
	if user := firstNonEmpty(values["user"], values["username"], values["userid"], values["user_id"], normalizePotentialAccount(f.PotentialAccount)); user != "" {
		fields = append(fields, credentialField{Label: "User", Value: user})
	}
	if bundle := firstNonEmpty(values["bundle"], values["certificate"], values["cert"], values["pfx"], values["p12"]); bundle != "" {
		fields = append(fields, credentialField{Label: "Bundle", Value: bundle})
	}
	if domain := firstNonEmpty(values["domain"], values["domene"]); domain != "" {
		fields = append(fields, credentialField{Label: "Domain", Value: domain})
	}
	if host := firstNonEmpty(values["host"], values["server"], values["remote"]); host != "" {
		fields = append(fields, credentialField{Label: "Host", Value: host})
	}
	fields = append(fields, credentialField{Label: exportFieldLabel(secretLabel), Value: secretValue})
	dedup := fmt.Sprintf("generic::%s::%s::%s::%s", group, secretLabel, secretValue, firstNonEmpty(values["user"], normalizePotentialAccount(f.PotentialAccount)))
	return credentialEntry{
		Group:    group,
		SortKey:  exportSourcePath(f),
		DedupKey: dedup,
		Paths:    []string{exportSourcePath(f)},
		Fields:   fields,
	}, true
}

func exportSourcePath(f scanner.Finding) string {
	return uncPath(f)
}

func joinNonEmpty(values ...string) string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return strings.Join(out, "\n")
}

func parseAssignmentValues(text string) map[string]string {
	values := make(map[string]string)
	text = strings.ReplaceAll(text, "\r\n", "\n")
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		for _, sep := range []string{"=", ":"} {
			if idx := strings.Index(line, sep); idx > 0 {
				key := normalizeAssignmentKey(line[:idx])
				value := strings.TrimSpace(strings.Trim(line[idx+1:], `"'`))
				if key != "" && value != "" {
					values[key] = value
				}
				break
			}
		}
	}
	return values
}

func normalizeAssignmentKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "_")
	value = strings.ReplaceAll(value, "-", "_")
	return value
}

func bestSecretValue(values map[string]string) (string, string) {
	orderedKeys := []string{
		"password",
		"passord",
		"pwd",
		"db_password",
		"secret",
		"client_secret",
		"shared_secret",
		"api_key",
		"apikey",
		"token",
		"access_token",
	}
	for _, key := range orderedKeys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return key, value
		}
	}
	return "", ""
}

func exportFieldLabel(key string) string {
	switch key {
	case "password", "passord", "pwd", "db_password":
		return "Password"
	case "client_secret", "shared_secret", "secret":
		return "Secret"
	case "api_key", "apikey":
		return "APIKey"
	case "token", "access_token":
		return "Token"
	default:
		return strings.Title(strings.ReplaceAll(key, "_", " "))
	}
}

func normalizePotentialAccount(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, prefix := range []string{"user =", "username =", "account =", "login ="} {
		if strings.HasPrefix(strings.ToLower(value), prefix) {
			return strings.TrimSpace(value[len(prefix):])
		}
	}
	return ""
}

func awsProfileName(f scanner.Finding) string {
	for _, tag := range f.Tags {
		tag = strings.TrimSpace(tag)
		if strings.HasPrefix(tag, "aws:profile:") {
			return strings.TrimPrefix(tag, "aws:profile:")
		}
	}
	values := parseAssignmentValues(joinNonEmpty(f.Context, f.MatchedText))
	if profile := firstNonEmpty(values["profile"], values["role_arn"]); profile != "" {
		return profile
	}
	return ""
}

type databaseCredential struct {
	host     string
	database string
	user     string
	password string
	raw      string
}

func parseDatabaseCredential(raw string) databaseCredential {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return databaseCredential{}
	}
	if parsed, ok := parseDatabaseURL(raw); ok {
		parsed.raw = raw
		return parsed
	}
	parsed := parseDatabaseSemicolonKV(raw)
	parsed.raw = raw
	return parsed
}

func parseDatabaseURL(raw string) (databaseCredential, bool) {
	value := strings.TrimSpace(raw)
	if strings.HasPrefix(strings.ToLower(value), "jdbc:") {
		value = value[5:]
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed == nil {
		return databaseCredential{}, false
	}
	if parsed.Scheme == "" || parsed.Host == "" || parsed.User == nil {
		return databaseCredential{}, false
	}
	password, ok := parsed.User.Password()
	if !ok || strings.TrimSpace(password) == "" {
		return databaseCredential{}, false
	}
	dbName := strings.Trim(strings.TrimSpace(parsed.Path), "/")
	return databaseCredential{
		host:     parsed.Hostname(),
		database: dbName,
		user:     parsed.User.Username(),
		password: password,
	}, true
}

func parseDatabaseSemicolonKV(raw string) databaseCredential {
	values := make(map[string]string)
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		for _, sep := range []string{"=", ":"} {
			if idx := strings.Index(part, sep); idx > 0 {
				key := normalizeAssignmentKey(part[:idx])
				value := strings.TrimSpace(strings.Trim(part[idx+1:], `"'`))
				if key != "" && value != "" {
					values[key] = value
				}
				break
			}
		}
	}
	return databaseCredential{
		host:     firstNonEmpty(values["server"], values["host"], values["datasource"], values["data_source"]),
		database: firstNonEmpty(values["database"], values["dbname"], values["initialcatalog"], values["initial_catalog"], values["service_name"], values["servicename"]),
		user:     firstNonEmpty(values["user_id"], values["userid"], values["uid"], values["user"], values["username"]),
		password: firstNonEmpty(values["password"], values["pwd"]),
	}
}

func looksPlaceholderCredential(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	placeholderTokens := []string{
		"changeme",
		"default",
		"demo",
		"dummy",
		"example",
		"fake",
		"placeholder",
		"sample",
		"test",
	}
	for _, token := range placeholderTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
