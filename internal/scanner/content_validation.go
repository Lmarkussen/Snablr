package scanner

import (
	"regexp"
	"strings"

	"snablr/internal/credentialanalysis"
)

var placeholderValueTokens = []string{
	"changeme",
	"placeholder",
	"replace_me",
	"replace-me",
	"replace_this",
	"replace-this",
	"your_password",
	"your-password",
	"your_username",
	"your-username",
	"your_server",
	"your-server",
	"your_database",
	"your-database",
	"example_password",
	"example_secret",
	"example_token",
	"<password>",
	"<secret>",
	"<token>",
	"<username>",
	"<server>",
	"<database>",
}

func shouldSuppressWeakContentMatch(ruleID string, category string, matchedText string, context string) bool {
	suppress, _ := weakContentSuppression(ruleID, category, matchedText, context)
	return suppress
}

func weakContentSuppression(ruleID string, category string, matchedText string, context string) (bool, string) {
	blob := strings.TrimSpace(firstNonEmptyString(context, matchedText))
	if blob == "" {
		return false, ""
	}

	switch ruleID {
	case "content.database_connection_string_indicators":
		if assessConnectionStringQuality(blob).Weak {
			return true, "connection string values look placeholder-like or weak"
		}
		return false, ""
	case "content.credential_note_indicators":
		// A bare keyword ("credentials", "PW", "pwd") on its own line is a word
		// or dictionary entry, not a credential note. A note must add a label,
		// qualifier or value alongside the keyword.
		if isBareCredentialNoteKeyword(matchedText) {
			return true, "credential-note keyword appeared without associated credential content"
		}
		if isCredentialPolicyDocumentation(matchedText) {
			return true, "credential-note match is password policy documentation"
		}
		values := extractedSensitiveValues(matchedText)
		quality := assessExtractedValuesQuality(values)
		if len(values) > 0 && quality.Weak && !quality.LengthOnly {
			return true, "credential-note value looks placeholder-like or low quality"
		}
		return false, ""
	case "content.note_style_credential_pair_indicators":
		// The rule matches the account line; the paired secret is on the
		// surrounding lines. When every paired secret value is a placeholder or
		// an unresolved reference ("CHANGE_ME", "********", "${DEPLOY_PASSWORD}")
		// there is no credential to report, matching how the credential
		// harvester treats the same values. Any real secret keeps the finding,
		// and notes without a visible secret line keep the default handling.
		secrets := pairedSecretValues(context)
		if len(secrets) > 0 && allPlaceholderValues(secrets) {
			return true, "paired secret values are placeholders or unresolved references"
		}
		// A line that names an account in DOMAIN\user or user@domain form,
		// with no secret anywhere around it, is an identity (a log or
		// transcript header such as "Username: HOST\admin"), not a
		// credential pair.
		if len(secrets) == 0 {
			if pair, ok := parseGenericPairLine(matchedText); ok && isQualifiedAccountName(pair.Value) {
				return true, "account name without a paired secret"
			}
		}
	case "content.password_note_value_indicators":
		// "...the service account password available." is prose: the word
		// after "password" ends a sentence or is ordinary vocabulary.
		if match := passwordNoteValuePattern.FindStringSubmatch(matchedText); match != nil && isProseWord(match[1]) {
			return true, "password mention is prose, not a value"
		}
	case "content.password_assignment_indicators":
		// An explicit "<password> = <value>" assignment states a credential
		// outright. Shortness alone is therefore not enough to withhold the
		// finding: weak, predictable and PIN-like credentials are exactly what has
		// to be discovered, and the value has already passed the bounded grammar.
		// Placeholder-like and low-entropy values are still suppressed, and the
		// finding itself keeps its low confidence from the same value-quality
		// assessment.
		matchedValues := extractedSensitiveValues(matchedText)
		if len(matchedValues) == 0 {
			// Keys such as "ndesServiceAccountPassword" are not split out by
			// the value extractor; read the assigned value directly.
			if value, ok := assignedValue(matchedText); ok {
				matchedValues = []string{value}
			}
		}
		if allPlaceholderValues(matchedValues) {
			return true, "assigned values are placeholders or unresolved references"
		}
		matchedQuality := assessExtractedValuesQuality(matchedValues)
		if len(matchedValues) > 0 && matchedQuality.Weak && !matchedQuality.LengthOnly {
			return true, "sensitive values look placeholder-like or low quality"
		}
		values := extractedSensitiveValues(blob)
		if allNonSecretValueShapes(values) {
			return true, "assigned value looks like a SQL/config fragment rather than a secret"
		}
		quality := assessExtractedValuesQuality(values)
		if quality.Weak && !quality.LengthOnly {
			return true, "sensitive values look placeholder-like or low quality"
		}
		return false, ""
	}

	switch strings.ToLower(strings.TrimSpace(category)) {
	case "credentials", "infrastructure":
		// Values the credential layer recognises as placeholders or unresolved
		// references ("CHANGE_ME", "${DEPLOY_PASSWORD}") are not credentials.
		// Only the matched text is considered, so a real value nearby is never
		// hidden by this check.
		if matched := extractedSensitiveValues(matchedText); allPlaceholderValues(matched) {
			return true, "matched values are placeholders or unresolved references"
		}
		if assessExtractedValuesQuality(extractedSensitiveValues(blob)).Weak {
			return true, "sensitive values look placeholder-like or low quality"
		}
		return false, ""
	default:
		return false, ""
	}
}

func extractedSensitiveValues(blob string) []string {
	var values []string
	for _, match := range assignmentSecretRegex.FindAllStringSubmatch(blob, -1) {
		if len(match) >= 5 {
			values = append(values, match[4])
		}
	}
	for _, match := range xmlSecretRegex.FindAllStringSubmatch(blob, -1) {
		if len(match) >= 3 {
			values = append(values, match[2])
		}
	}
	for _, match := range xmlAddValueRegex.FindAllStringSubmatch(blob, -1) {
		if len(match) >= 3 && isSecretLabel(match[1]) {
			values = append(values, match[2])
		}
	}
	for _, match := range xmlSecretAttrRegex.FindAllStringSubmatch(blob, -1) {
		if len(match) >= 3 {
			values = append(values, match[2])
		}
	}
	for _, line := range strings.Split(blob, "\n") {
		if match, ok := parseGenericPairLine(line); ok {
			values = append(values, match.Value)
		}
	}
	return values
}

func hasMeaningfulConnectionStringEvidence(blob string) bool {
	quality := assessConnectionStringQuality(blob)
	return !quality.Weak && quality.Score >= 10
}

// allNonSecretValueShapes reports whether every extracted value is, by shape,
// a non-secret fragment (SQL variable, expression, schema/metadata definition,
// boolean fragment or prose). When true, the surrounding credential-like label
// is not evidence of a secret.
func allNonSecretValueShapes(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if _, reject := credentialanalysis.NonSecretValueShape(value); !reject {
			return false
		}
	}
	return true
}

// isBareCredentialNoteKeyword reports whether a matched credential-note phrase
// consists solely of a single credential keyword, with no account label,
// qualifier, separator or value attached. Dictionary/wordlist entries look like
// this and must not be treated as credential notes.
func isBareCredentialNoteKeyword(matched string) bool {
	line := strings.TrimSpace(strings.SplitN(matched, "\n", 2)[0])
	if line == "" {
		return false
	}
	if strings.ContainsAny(line, ":=-*;") {
		return false
	}
	fields := strings.Fields(line)
	if len(fields) != 1 {
		return false
	}
	switch strings.ToLower(strings.Trim(fields[0], "#;*-> ")) {
	case "cred", "creds", "credential", "credentials", "password", "passwords",
		"passord", "pw", "pwd", "login", "account":
		return true
	default:
		return false
	}
}

func isCredentialPolicyDocumentation(matched string) bool {
	line := strings.ToLower(strings.TrimSpace(strings.SplitN(matched, "\n", 2)[0]))
	return strings.Contains(line, "password policy") &&
		(strings.Contains(line, "choose") || strings.Contains(line, "strong") || strings.Contains(line, "never store"))
}

func isPlaceholderSecretValue(value string) bool {
	value = strings.ToLower(strings.TrimSpace(strings.Trim(value, `"'`)))
	if credentialanalysis.IsPlaceholderValue(value) {
		return true
	}
	switch {
	case value == "":
		return true
	case strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">"):
		return true
	case strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}"):
		return true
	case strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}"):
		return true
	}
	switch value {
	case "password", "secret", "token", "username", "server", "database":
		return true
	}
	for _, token := range placeholderValueTokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func containsAnyToken(value string, parts ...string) bool {
	for _, part := range parts {
		if strings.Contains(value, part) {
			return true
		}
	}
	return false
}

// pairedSecretLinePattern parses one "key: value" or "key = value" line.
var pairedSecretLinePattern = regexp.MustCompile(`^\s*([\p{L}][\p{L}\p{N}_. -]{0,63}?)\s*[:=]\s*(.*?)\s*$`)

// pairedSecretValues returns the values of password-role fields in a match
// context, using the credential harvester's field vocabulary.
func pairedSecretValues(context string) []string {
	var values []string
	for _, line := range strings.Split(context, "\n") {
		match := pairedSecretLinePattern.FindStringSubmatch(line)
		if match == nil || credentialanalysis.ClassifyFieldName(match[1]) != credentialanalysis.FieldRolePassword {
			continue
		}
		value := strings.Trim(strings.TrimSpace(match[2]), `"'`)
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

func allPlaceholderValues(values []string) bool {
	for _, value := range values {
		if !credentialanalysis.IsPlaceholderValue(value) {
			return false
		}
	}
	return len(values) > 0
}

var (
	passwordNoteValuePattern = regexp.MustCompile(`(?i)\b(?:password|passord)\b(?:[ \t]+is[ \t]+|[ \t]*[:=][ \t]*|[ \t]+)(\S{4,64})[ \t]*$`)
	qualifiedAccountPattern  = regexp.MustCompile(`^(?:[A-Za-z0-9][A-Za-z0-9._-]*\\[A-Za-z0-9][A-Za-z0-9._$-]*|[A-Za-z0-9][A-Za-z0-9._-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$`)
)

// proseWords commonly follow "password" in documentation and log text.
var proseWords = map[string]struct{}{
	"available": {}, "required": {}, "needed": {}, "expired": {}, "changed": {}, "reset": {},
	"protected": {}, "encrypted": {}, "stored": {}, "provided": {}, "missing": {}, "incorrect": {},
	"policy": {}, "prompt": {}, "field": {}, "below": {}, "above": {}, "here": {}, "there": {},
}

// isProseWord reports whether the word after "password" is prose: a lowercase
// word that ends a sentence or is common documentation vocabulary.
func isProseWord(value string) bool {
	word := strings.TrimRight(value, ".,;:!?")
	if word == "" {
		return false
	}
	for _, r := range word {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	if word != value && strings.HasSuffix(value, ".") {
		return true
	}
	_, ok := proseWords[word]
	return ok
}

// isQualifiedAccountName reports whether a value is a DOMAIN\user or
// user@domain account name.
func isQualifiedAccountName(value string) bool {
	return qualifiedAccountPattern.MatchString(strings.TrimSpace(value))
}

// assignedValue returns the value of a single "key = value" or "key: value"
// assignment, without trailing statement terminators.
func assignedValue(text string) (string, bool) {
	index := strings.IndexAny(text, "=:")
	if index < 0 {
		return "", false
	}
	value := strings.TrimSpace(strings.TrimRight(strings.TrimSpace(text[index+1:]), ";,"))
	return value, value != ""
}
