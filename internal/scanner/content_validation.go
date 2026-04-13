package scanner

import "strings"

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
	}

	switch strings.ToLower(strings.TrimSpace(category)) {
	case "credentials", "infrastructure":
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

func isPlaceholderSecretValue(value string) bool {
	value = strings.ToLower(strings.TrimSpace(strings.Trim(value, `"'`)))
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
