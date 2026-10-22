package cloudinspect

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strconv"
	"testing"
)

func TestInspectOfflineCloudArtifacts(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	key := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	tests := []struct {
		name string
		doc  map[string]any
		want string
	}{
		{
			name: "aws application bundle",
			doc:  map[string]any{"aws_access_key_id": "AKIA0000000000000001", "aws_secret_access_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			want: "cloudinspect.aws.application_bundle",
		},
		{
			name: "azure client secret",
			doc:  map[string]any{"tenant_id": "00000000-0000-4000-8000-000000000001", "client_id": "00000000-0000-4000-8000-000000000002", "client_secret": "synthetic-azure-secret"},
			want: "cloudinspect.azure.client_secret_config",
		},
		{
			name: "gcp service account",
			doc:  map[string]any{"type": "service_account", "project_id": "synthetic-project", "private_key_id": "key-1", "private_key": key, "client_email": "svc@synthetic-project.iam.gserviceaccount.com"},
			want: "cloudinspect.gcp.service_account",
		},
		{
			name: "gcp external account",
			doc:  map[string]any{"type": "external_account", "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/providers/provider", "subject_token_type": "urn:ietf:params:oauth:token-type:jwt", "credential_source": map[string]any{"file": "/var/run/token"}},
			want: "cloudinspect.gcp.external_account",
		},
	}
	inspector := New()
	for _, test := range tests {
		content, err := json.Marshal(test.doc)
		if err != nil {
			t.Fatal(err)
		}
		matches := inspector.InspectContent(Candidate{Name: test.name + ".opaque", Extension: ""}, content)
		if len(matches) != 1 || matches[0].ID != test.want {
			t.Fatalf("%s: matches = %#v, want %s", test.name, matches, test.want)
		}
		if matches[0].MatchedText != string(content) || matches[0].Context != string(content) {
			t.Fatalf("%s: original evidence was not preserved", test.name)
		}
	}
}

func TestInspectRejectsReferencesMalformedAndIdentifiers(t *testing.T) {
	negative := []map[string]any{
		{"tenant_id": "00000000-0000-4000-8000-000000000001", "client_id": "00000000-0000-4000-8000-000000000002", "client_secret": "${AZURE_CLIENT_SECRET}"},
		{"type": "external_account", "audience": "audience", "subject_token_type": "jwt", "credential_source": map[string]any{}},
		{"type": "service_account", "project_id": "project", "private_key_id": "id", "client_email": "svc@example.test", "private_key": "PRIVATE KEY PATH"},
		{"client_id": "00000000-0000-4000-8000-000000000002", "tenant_id": "00000000-0000-4000-8000-000000000001"},
	}
	inspector := New()
	for index, document := range negative {
		content, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if matches := inspector.InspectContent(Candidate{Name: "negative.opaque", Extension: ""}, content); len(matches) != 0 {
			t.Fatalf("negative %d produced matches: %#v", index, matches)
		}
	}
}

func TestInspectFindsIndependentNestedRecordsWithoutCrossScopePairing(t *testing.T) {
	document := map[string]any{
		"production": map[string]any{
			"aws_access_key_id":     "AKIA0000000000000001",
			"aws_secret_access_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		"reporting": map[string]any{
			"aws_access_key_id":     "AKIA0000000000000002",
			"aws_secret_access_key": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		"azure": map[string]any{
			"service_principals": []any{
				map[string]any{"tenant_id": "00000000-0000-4000-8000-000000000001", "client_id": "00000000-0000-4000-8000-000000000002", "client_secret": "azure-production-secret"},
				map[string]any{"tenant_id": "00000000-0000-4000-8000-000000000003", "client_id": "00000000-0000-4000-8000-000000000004", "client_secret": "azure-reporting-secret"},
			},
		},
		"incomplete": map[string]any{"aws_access_key_id": "AKIA0000000000000003"},
	}
	content, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	matches := New().InspectContent(Candidate{Name: "mixed.opaque"}, content)
	if len(matches) != 4 {
		t.Fatalf("matches = %#v, want four independently scoped records", matches)
	}
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if match.ObservationKey == "" || match.Match == match.ID {
			t.Fatalf("missing source-local observation discriminator: %#v", match)
		}
		if _, exists := seen[match.ObservationKey]; exists {
			t.Fatalf("duplicate source-local observation key: %#v", matches)
		}
		seen[match.ObservationKey] = struct{}{}
		if match.MatchedText != string(content) || match.Context != string(content) {
			t.Fatal("complete source evidence was not retained")
		}
	}
}

func TestInspectDeterministicMultiSeedCorpus(t *testing.T) {
	tests := []struct {
		seed      int
		content   string
		wantCount int
		wantTypes []string
	}{
		{1, `{"prod":{"aws_access_key_id":"AKIA0000000000000001","aws_secret_access_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"report":{"aws_access_key_id":"AKIA0000000000000002","aws_secret_access_key":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}`, 2, []string{"cloudinspect.aws.application_bundle", "cloudinspect.aws.application_bundle"}},
		{2, `{"principals":[{"tenant_id":"00000000-0000-4000-8000-000000000001","client_id":"00000000-0000-4000-8000-000000000002","client_secret":"azure-one"},{"tenant_id":"00000000-0000-4000-8000-000000000003","client_id":"00000000-0000-4000-8000-000000000004","client_secret":"azure-two"}]}`, 2, []string{"cloudinspect.azure.client_secret_config", "cloudinspect.azure.client_secret_config"}},
		{3, `{"external":{"type":"external_account","audience":"audience-one","subject_token_type":"jwt","credential_source":{"file":"token-one"}},"incomplete":{"type":"external_account","audience":"audience-two","subject_token_type":"jwt","credential_source":{}}}`, 1, []string{"cloudinspect.gcp.external_account"}},
		{4, `{"gcp":{"type":"service_account","project_id":"project","private_key_id":"key","client_email":"svc@project.example","private_key":"not-a-key"},"public":{"tenant_id":"00000000-0000-4000-8000-000000000001","client_id":"00000000-0000-4000-8000-000000000002"}}`, 0, nil},
	}
	for _, test := range tests {
		matches := New().InspectContent(Candidate{Name: "seed-" + strconv.Itoa(test.seed)}, []byte(test.content))
		if len(matches) != test.wantCount {
			t.Fatalf("seed %d: got %d matches %#v, want %d", test.seed, len(matches), matches, test.wantCount)
		}
		for index, wantType := range test.wantTypes {
			if matches[index].ID != wantType || matches[index].ObservationKey == "" {
				t.Fatalf("seed %d match %d = %#v, want %s with observation key", test.seed, index, matches[index], wantType)
			}
		}
	}
}
