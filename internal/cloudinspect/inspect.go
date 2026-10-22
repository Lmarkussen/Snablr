package cloudinspect

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Candidate struct {
	FilePath  string
	Name      string
	Extension string
	Size      int64
}

type Match struct {
	ID                  string
	Name                string
	Description         string
	RuleType            string
	SignalType          string
	Severity            string
	Confidence          string
	Category            string
	Match               string
	MatchedText         string
	MatchedTextRedacted string
	Snippet             string
	Context             string
	ContextRedacted     string
	LineNumber          int
	Explanation         string
	Remediation         string
	Tags                []string
	ObservationKey      string
}

type Inspector struct{}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
var awsAccessKeyPattern = regexp.MustCompile(`^(AKIA|ASIA)[A-Z0-9]{16}$`)
var awsSecretKeyPattern = regexp.MustCompile(`^[A-Za-z0-9/+=]{40}$`)

func New() Inspector { return Inspector{} }

func (Inspector) NeedsContent(candidate Candidate) bool {
	return strings.EqualFold(candidate.Extension, ".json") || strings.HasSuffix(strings.ToLower(candidate.Name), ".json")
}

func (Inspector) InspectContent(candidate Candidate, content []byte) []Match {
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		return nil
	}
	text := string(content)
	matches := make([]Match, 0, 4)
	walkJSON(document, "$", text, &matches)
	return matches
}

func walkJSON(document map[string]any, jsonPath, text string, matches *[]Match) {
	if isAWSApplicationBundle(document) {
		*matches = append(*matches, configMatch(
			"cloudinspect.aws.application_bundle",
			"AWS Application Credential Bundle",
			"An application configuration contains a structurally valid AWS access-key and secret-key pair.",
			"aws", "aws:type:application-bundle", "Configured AWS application credentials were recognized offline; provider acceptance was not tested.", jsonPath, text,
		))
	}
	if isAzureClientSecret(document) {
		*matches = append(*matches, configMatch(
			"cloudinspect.azure.client_secret_config",
			"Azure Client Secret Configuration",
			"An application configuration contains tenant, client, and non-placeholder client-secret fields.",
			"azure", "azure:type:client-secret-config", "Configured Azure client-secret material was recognized offline; authentication was not tested.", jsonPath, text,
		))
	}
	if isGCPServiceAccount(document) {
		*matches = append(*matches, configMatch(
			"cloudinspect.gcp.service_account",
			"Google Cloud Service Account Configuration",
			"A Google Cloud service-account JSON document contains required identity fields and a structurally valid private-key block.",
			"gcp", "gcp:type:service-account", "The embedded private key remains owned by the private-key detector; this finding represents the surrounding service-account configuration.", jsonPath, text,
		))
	}
	if isGCPExternalAccount(document) {
		*matches = append(*matches, configMatch(
			"cloudinspect.gcp.external_account",
			"Google Cloud External Account Configuration",
			"A Google Cloud external-account configuration contains an audience, subject-token type, and credential-source reference.",
			"gcp", "gcp:type:external-account", "This is a source-backed workload-identity reference; no private key or active credential was recovered.", jsonPath, text,
		))
	}
	keys := make([]string, 0, len(document))
	for key := range document {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		switch child := document[key].(type) {
		case map[string]any:
			walkJSON(child, jsonPath+"."+key, text, matches)
		case []any:
			for index, item := range child {
				if object, ok := item.(map[string]any); ok {
					walkJSON(object, jsonPath+"."+key+"["+strconv.Itoa(index)+"]", text, matches)
				}
			}
		}
	}
}

func configMatch(id, name, description, provider, tag, explanation, jsonPath, text string) Match {
	return Match{
		ID: id, Name: name, Description: description, RuleType: "content", SignalType: "validated",
		Severity: "high", Confidence: "high", Category: "cloud", Match: id + " at " + jsonPath, MatchedText: text,
		MatchedTextRedacted: text, Snippet: text, Context: text, ContextRedacted: text,
		Explanation: explanation, Remediation: "Restrict access to cloud configuration material and rotate recovered secrets through the provider's normal controls.",
		Tags:           []string{"cloud", provider, "artifact:cloud-configuration", tag},
		ObservationKey: jsonPath,
	}
}

func isAWSApplicationBundle(document map[string]any) bool {
	accessKey, accessOK := stringField(document, "aws_access_key_id")
	secretKey, secretOK := stringField(document, "aws_secret_access_key")
	return accessOK && secretOK && awsAccessKeyPattern.MatchString(accessKey) && awsSecretKeyPattern.MatchString(secretKey)
}

func isAzureClientSecret(document map[string]any) bool {
	tenant, tenantOK := stringField(document, "tenant_id")
	client, clientOK := stringField(document, "client_id")
	secret, secretOK := stringField(document, "client_secret")
	return tenantOK && clientOK && secretOK && uuidPattern.MatchString(tenant) && uuidPattern.MatchString(client) && literalSecret(secret)
}

func isGCPServiceAccount(document map[string]any) bool {
	typeName, typeOK := stringField(document, "type")
	project, projectOK := stringField(document, "project_id")
	keyID, keyIDOK := stringField(document, "private_key_id")
	email, emailOK := stringField(document, "client_email")
	privateKey, privateKeyOK := stringField(document, "private_key")
	if !typeOK || !projectOK || !keyIDOK || !emailOK || !privateKeyOK || typeName != "service_account" || project == "" || keyID == "" || !strings.Contains(email, "@") {
		return false
	}
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") {
		return false
	}
	_, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	return err == nil
}

func isGCPExternalAccount(document map[string]any) bool {
	typeName, typeOK := stringField(document, "type")
	audience, audienceOK := stringField(document, "audience")
	subjectType, subjectOK := stringField(document, "subject_token_type")
	source, sourceOK := document["credential_source"].(map[string]any)
	return typeOK && typeName == "external_account" && audienceOK && audience != "" && subjectOK && subjectType != "" && sourceOK && len(source) > 0
}

func stringField(document map[string]any, key string) (string, bool) {
	value, ok := document[key].(string)
	return strings.TrimSpace(value), ok && strings.TrimSpace(value) != ""
}

func literalSecret(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" || strings.Contains(lower, "example") || strings.Contains(lower, "placeholder") || strings.Contains(lower, "changeme") || strings.ContainsAny(lower, "${}") {
		return false
	}
	return true
}
