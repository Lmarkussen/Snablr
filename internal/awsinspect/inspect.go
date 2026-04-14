package awsinspect

import (
	"bufio"
	"path"
	"regexp"
	"strings"

	"snablr/internal/rules"
	"snablr/internal/textdecode"
)

type artifactKind string

const (
	artifactNone        artifactKind = ""
	artifactCredentials artifactKind = "credentials"
	artifactConfig      artifactKind = "config"
)

var (
	credentialsBackupPattern = regexp.MustCompile(`^credentials\.(bak|old|backup|copy)$`)
	configBackupPattern      = regexp.MustCompile(`^config\.(bak|old|backup|copy)$`)
	accessKeyPattern         = regexp.MustCompile(`^(AKIA|ASIA)[A-Z0-9]{16}$`)
	secretKeyPattern         = regexp.MustCompile(`^[A-Za-z0-9/+=]{40}$`)
	sessionTokenPattern      = regexp.MustCompile(`^[A-Za-z0-9/+=_-]{60,}$`)
)

func New() Inspector {
	return Inspector{}
}

func (Inspector) NeedsContent(candidate Candidate) bool {
	kind, _ := classifyAWSArtifact(candidate.FilePath)
	return kind != artifactNone
}

func (Inspector) InspectMetadata(candidate Candidate) []Match {
	kind, normalized := classifyAWSArtifact(candidate.FilePath)
	if kind == artifactNone {
		return nil
	}

	match := Match{
		RuleType:            "filename",
		SignalType:          "validated",
		Confidence:          "high",
		MatchedText:         normalized,
		MatchedTextRedacted: normalized,
		Snippet:             normalized,
		Context:             normalized,
		ContextRedacted:     normalized,
		LineNumber:          1,
		Remediation:         "Restrict access to exposed AWS profile material, remove unnecessary copies from shared storage, and rotate AWS credentials if confirmed.",
	}

	switch kind {
	case artifactCredentials:
		match.ID = "awsinspect.path.credentials"
		match.Name = "AWS Credentials Artifact"
		match.Description = "This path matches an exact AWS CLI/shared-credentials artifact or backup variant under a `.aws` profile directory."
		match.Severity = "high"
		match.Category = "cloud"
		match.Match = ".aws/credentials"
		match.Explanation = "This path is an AWS shared credentials artifact and is high-value when it contains real key material."
		match.Tags = []string{"aws", "cloud", "artifact:aws-credentials", "aws:type:credentials"}
	case artifactConfig:
		match.ID = "awsinspect.path.config"
		match.Name = "AWS Config Artifact"
		match.Description = "This path matches an exact AWS CLI/shared-config artifact or backup variant under a `.aws` profile directory."
		match.Severity = "medium"
		match.Category = "infrastructure"
		match.Match = ".aws/config"
		match.Explanation = "This path is an AWS shared config artifact and is most useful as supporting context unless it also contains credential material."
		match.Tags = []string{"aws", "cloud", "artifact:aws-config", "aws:type:config"}
	}

	return []Match{match}
}

func (Inspector) InspectContent(candidate Candidate, content []byte) []Match {
	kind, _ := classifyAWSArtifact(candidate.FilePath)
	if kind == artifactNone || len(content) == 0 {
		return nil
	}

	text := textdecode.Normalize(content)
	if text == "" {
		return nil
	}

	accessKey, secretKey, sessionToken, lineNumber, profile := extractAWSCredentialBundle(text)
	if accessKey == "" || secretKey == "" {
		return nil
	}

	matchedLines := []string{
		"aws_access_key_id=" + accessKey,
		"aws_secret_access_key=" + secretKey,
	}
	matchLabel := "aws_access_key_id + aws_secret_access_key"
	tags := []string{"aws", "cloud", "credentials", "artifact:aws-credentials", "aws:type:bundle"}
	severity := "critical"
	explanation := "Structured AWS shared-credentials material was identified from exact AWS profile keys with real-looking credential values."
	if sessionToken != "" {
		matchedLines = append(matchedLines, "aws_session_token="+sessionToken)
		matchLabel = "aws_access_key_id + aws_secret_access_key + aws_session_token"
		tags = append(tags, "aws:type:session-bundle")
		explanation = "Structured AWS temporary session credentials were identified from exact AWS profile keys with real-looking credential values."
	}
	if strings.TrimSpace(profile) != "" {
		tags = append(tags, "aws:profile:"+sanitizeTagValue(profile))
	}

	context := strings.Join(matchedLines, "\n")
	return []Match{{
		ID:                  "awsinspect.content.credentials_bundle",
		Name:                "AWS Credential Bundle",
		Description:         "Detect exact AWS shared-credentials key bundles when real-looking access key and secret key material appear together.",
		RuleType:            "content",
		SignalType:          "validated",
		Severity:            severity,
		Confidence:          "high",
		Category:            "credentials",
		Match:               matchLabel,
		MatchedText:         context,
		MatchedTextRedacted: redactBundle(accessKey, secretKey, sessionToken),
		Snippet:             redactBundle(accessKey, secretKey, sessionToken),
		Context:             context,
		ContextRedacted:     redactBundle(accessKey, secretKey, sessionToken),
		LineNumber:          lineNumber,
		Explanation:         explanation,
		Remediation:         "Restrict access immediately, rotate exposed AWS credentials, and move CLI credential material into approved secret-management workflows.",
		Tags:                tags,
	}}
}

func classifyAWSArtifact(filePath string) (artifactKind, string) {
	normalized := normalizedPath(filePath)
	if normalized == "" || !strings.Contains(normalized, "/.aws/") {
		return artifactNone, ""
	}

	base := strings.ToLower(strings.TrimSpace(path.Base(normalized)))
	switch {
	case base == "credentials" || credentialsBackupPattern.MatchString(base):
		return artifactCredentials, normalized
	case base == "config" || configBackupPattern.MatchString(base):
		return artifactConfig, normalized
	default:
		return artifactNone, ""
	}
}

func normalizedPath(value string) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), `\`, `/`)
	return strings.ToLower(rules.NormalizePath(value))
}

func ProfileContext(pathValue string) string {
	normalized := normalizedPath(pathValue)
	if normalized == "" {
		return ""
	}
	if idx := strings.Index(normalized, "/.aws/"); idx > 0 {
		return strings.Trim(normalized[:idx], "/")
	}
	return ""
}

func extractAWSCredentialBundle(content string) (string, string, string, int, string) {
	scanner := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(content, "\r\n", "\n")))
	lineNumber := 0
	firstLine := 0
	profile := ""
	accessKey := ""
	secretKey := ""
	sessionToken := ""

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			profile = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}
		key, value, ok := splitAssignment(line)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "aws_access_key_id":
			if accessKeyPattern.MatchString(value) && !looksPlaceholder(value) {
				accessKey = value
				if firstLine == 0 {
					firstLine = lineNumber
				}
			}
		case "aws_secret_access_key":
			if secretKeyPattern.MatchString(value) && !looksPlaceholder(value) {
				secretKey = value
				if firstLine == 0 {
					firstLine = lineNumber
				}
			}
		case "aws_session_token":
			if sessionTokenPattern.MatchString(value) && !looksPlaceholder(value) {
				sessionToken = value
				if firstLine == 0 {
					firstLine = lineNumber
				}
			}
		}
	}

	return accessKey, secretKey, sessionToken, firstLine, profile
}

func splitAssignment(line string) (string, string, bool) {
	for _, separator := range []string{"=", ":"} {
		if idx := strings.Index(line, separator); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(strings.Trim(line[idx+1:], `"'`))
			if key != "" && value != "" {
				return key, value, true
			}
		}
	}
	return "", "", false
}

func looksPlaceholder(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return strings.Contains(lower, "example") ||
		strings.Contains(lower, "fake") ||
		strings.Contains(lower, "test") ||
		strings.Contains(lower, "changeme") ||
		strings.Contains(lower, "placeholder")
}

func redactBundle(accessKey, secretKey, sessionToken string) string {
	lines := []string{
		"aws_access_key_id=" + redactValue(accessKey),
		"aws_secret_access_key=" + redactValue(secretKey),
	}
	if strings.TrimSpace(sessionToken) != "" {
		lines = append(lines, "aws_session_token="+redactValue(sessionToken))
	}
	return strings.Join(lines, "\n")
}

func redactValue(value string) string {
	if len(value) <= 8 {
		return "********"
	}
	return value[:4] + "********"
}

func sanitizeTagValue(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "-")
	value = strings.ReplaceAll(value, "/", "-")
	return value
}
