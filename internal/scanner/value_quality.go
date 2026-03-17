package scanner

import (
	"math"
	"strings"
	"unicode"
)

type valueQuality struct {
	Score  int
	Label  string
	Reason string
	Weak   bool
	Strong bool
}

var weakValueBases = []string{
	"changeme",
	"default",
	"demo",
	"dummy",
	"example",
	"fake",
	"letmein",
	"password",
	"placeholder",
	"qwerty",
	"sample",
	"secret",
	"test",
	"token",
	"welcome",
}

func assessFindingValueQuality(f Finding) valueQuality {
	blob := firstNonEmptyString(f.Context, f.MatchedText, f.Match)

	switch {
	case hasSignalType(f, "validated"):
		if looksLikeConnectionMaterial(blob) {
			quality := assessConnectionStringQuality(blob)
			if quality.Score >= 14 {
				return quality
			}
		}
		switch strings.ToLower(strings.TrimSpace(f.Category)) {
		case "database-access", "credentials", "crypto", "deployment":
			return valueQuality{
				Score:  18,
				Label:  "high",
				Reason: "structured or validated evidence includes access details or secret-like material",
				Strong: true,
			}
		default:
			return valueQuality{
				Score:  14,
				Label:  "high",
				Reason: "structured or validated evidence was derived from parseable file content",
				Strong: true,
			}
		}

	case hasSignalType(f, "content"):
		if looksLikeConnectionMaterial(blob) {
			return assessConnectionStringQuality(blob)
		}

		quality := assessExtractedValuesQuality(extractedSensitiveValues(blob))
		if quality.Score > 0 {
			return quality
		}
		return valueQuality{
			Score:  8,
			Label:  "medium",
			Reason: "content evidence was captured from the file body",
		}

	case hasSignalType(f, "filename") || hasSignalType(f, "extension"):
		return valueQuality{
			Score:  0,
			Label:  "low",
			Reason: "confidence comes from metadata and context rather than extracted value quality",
		}
	default:
		return valueQuality{}
	}
}

func assessConnectionStringQuality(blob string) valueQuality {
	lower := strings.ToLower(strings.TrimSpace(blob))
	if lower == "" {
		return valueQuality{}
	}
	if !looksLikeConnectionMaterial(lower) {
		return valueQuality{}
	}

	values := extractedSensitiveValues(blob)
	if len(values) == 0 {
		return valueQuality{
			Score:  4,
			Label:  "low",
			Reason: "connection-like content was present, but no usable authentication value was extracted",
			Weak:   true,
		}
	}

	quality := assessExtractedValuesQuality(values)
	switch {
	case quality.Strong:
		quality.Score = maxInt(quality.Score, 16)
		quality.Reason = "connection string contains structural database fields and a strong non-placeholder authentication value"
	case quality.Weak:
		quality.Score = minInt(quality.Score, 4)
		quality.Reason = "connection-like content was present, but the extracted authentication value looks placeholder-like or weak"
	default:
		quality.Score = maxInt(quality.Score, 10)
		quality.Label = "medium"
		quality.Reason = "connection string contains structural database fields and a plausible authentication value"
	}
	return quality
}

func assessExtractedValuesQuality(values []string) valueQuality {
	if len(values) == 0 {
		return valueQuality{}
	}

	best := valueQuality{}
	weakCount := 0
	for _, raw := range values {
		quality := assessSensitiveValueQuality(raw)
		if quality.Weak {
			weakCount++
		}
		if quality.Score > best.Score {
			best = quality
		}
	}

	if best.Score == 0 && weakCount == len(values) {
		return valueQuality{
			Score:  2,
			Label:  "low",
			Reason: "content matched, but the nearby values look placeholder-like or weak",
			Weak:   true,
		}
	}

	if weakCount == len(values) && best.Score <= 4 {
		best.Weak = true
		best.Label = "low"
		if strings.TrimSpace(best.Reason) == "" {
			best.Reason = "content matched, but the nearby values look placeholder-like or weak"
		}
		return best
	}

	return best
}

func assessSensitiveValueQuality(value string) valueQuality {
	trimmed := strings.TrimSpace(strings.Trim(value, `"'`))
	if trimmed == "" {
		return valueQuality{
			Label:  "low",
			Reason: "value was empty after trimming",
			Weak:   true,
		}
	}
	if isPlaceholderSecretValue(trimmed) || isCommonWeakValue(trimmed) {
		return valueQuality{
			Score:  1,
			Label:  "low",
			Reason: "value looks like a placeholder or common sample credential",
			Weak:   true,
		}
	}

	length := len(trimmed)
	if length < 8 {
		return valueQuality{
			Score:  2,
			Label:  "low",
			Reason: "value is shorter than a plausible credential or secret",
			Weak:   true,
		}
	}

	entropy := shannonEntropy(trimmed)
	classes := characterClassCount(trimmed)
	unique := uniqueRuneCount(trimmed)
	if unique <= 2 {
		return valueQuality{
			Score:  2,
			Label:  "low",
			Reason: "value has too little variation to look usable",
			Weak:   true,
		}
	}
	if entropy < 1.8 || (entropy < 2.4 && classes < 2) {
		return valueQuality{
			Score:  3,
			Label:  "low",
			Reason: "value has low entropy and limited character diversity",
			Weak:   true,
		}
	}

	switch {
	case length >= 14 && unique >= 6 && (classes >= 3 || entropy >= 3.2):
		return valueQuality{
			Score:  18,
			Label:  "high",
			Reason: "value is long and has strong entropy or character diversity",
			Strong: true,
		}
	case length >= 10 && unique >= 5 && (classes >= 2 || entropy >= 2.7):
		return valueQuality{
			Score:  12,
			Label:  "medium",
			Reason: "value has plausible length and diversity for a real credential or secret",
		}
	default:
		return valueQuality{
			Score:  8,
			Label:  "medium",
			Reason: "value looks plausible, but only has moderate strength indicators",
		}
	}
}

func looksLikeConnectionMaterial(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return containsAnyToken(lower,
		"server=", "host=", "data source=", "datasource=", "initial catalog=", "database=",
		"uid=", "user id=", "username=", "pwd=", "password=", "jdbc:", "dsn=", "driver=",
	)
}

func isCommonWeakValue(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(strings.Trim(value, `"'`)))
	if normalized == "" {
		return true
	}

	collapsed := collapseAlphaNum(normalized)
	if collapsed == "" {
		return true
	}
	for _, base := range weakValueBases {
		if collapsed == base {
			return true
		}
		if allowsWeakNumericSuffix(base) && strings.HasPrefix(collapsed, base) && digitsOnly(strings.TrimPrefix(collapsed, base)) {
			return true
		}
	}
	return false
}

func allowsWeakNumericSuffix(base string) bool {
	switch base {
	case "changeme", "default", "demo", "dummy", "example", "fake", "placeholder", "sample", "test":
		return true
	default:
		return false
	}
}

func collapseAlphaNum(value string) string {
	var b strings.Builder
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

func digitsOnly(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func characterClassCount(value string) int {
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range value {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	count := 0
	for _, present := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if present {
			count++
		}
	}
	return count
}

func uniqueRuneCount(value string) int {
	seen := make(map[rune]struct{})
	for _, r := range value {
		seen[r] = struct{}{}
	}
	return len(seen)
}

func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}

	freq := make(map[rune]float64)
	total := 0.0
	for _, r := range value {
		freq[r]++
		total++
	}

	entropy := 0.0
	for _, count := range freq {
		p := count / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
