package awsinspect

import (
	"strings"
	"testing"
)

func testAWSAccessKey() string {
	return strings.Join([]string{"AKIA", "ABCDEFGHIJKLMNOP"}, "")
}

func testAWSSecretKey() string {
	return strings.Join([]string{"abcdEFGHijklMNOPqrstUVWXyz0123456789/+=", "A"}, "")
}

func testAWSSessionToken() string {
	return strings.Join([]string{
		"IQoJb3JpZ2luX2VjEKD//////////wEaCXVzLWVhc3QtMSJHMEUCIQDLABCD1234",
		"TOKEN5678VALUE90XYZ0ABCD",
	}, "")
}

func TestInspectMetadataRecognizesExactAWSArtifacts(t *testing.T) {
	t.Parallel()

	inspector := New()
	credMatches := inspector.InspectMetadata(Candidate{FilePath: `Users/Alice/.aws/credentials`})
	if len(credMatches) != 1 || credMatches[0].ID != "awsinspect.path.credentials" {
		t.Fatalf("expected credentials artifact match, got %#v", credMatches)
	}

	configMatches := inspector.InspectMetadata(Candidate{FilePath: `Archive/ProfileCopies/Bob/.aws/config.bak`})
	if len(configMatches) != 1 || configMatches[0].ID != "awsinspect.path.config" {
		t.Fatalf("expected config artifact match, got %#v", configMatches)
	}
}

func TestInspectContentRequiresRealCredentialBundle(t *testing.T) {
	t.Parallel()

	inspector := New()
	content := []byte("[default]\naws_access_key_id=" + testAWSAccessKey() + "\naws_secret_access_key=" + testAWSSecretKey() + "\naws_session_token=" + testAWSSessionToken() + "\n")
	matches := inspector.InspectContent(Candidate{FilePath: `Users/Alice/.aws/credentials`}, content)
	if len(matches) != 1 || matches[0].ID != "awsinspect.content.credentials_bundle" {
		t.Fatalf("expected credential bundle content match, got %#v", matches)
	}

	placeholder := []byte("[default]\naws_access_key_id=" + testAWSAccessKey() + "\naws_secret_access_key=EXAMPLE_SECRET_VALUE_SHOULD_NOT_PROMOTE1234\n")
	if got := inspector.InspectContent(Candidate{FilePath: `Users/Alice/.aws/credentials`}, placeholder); len(got) != 0 {
		t.Fatalf("expected placeholder values to be ignored, got %#v", got)
	}
}

func TestProfileContextUsesPrefixBeforeDotAWS(t *testing.T) {
	t.Parallel()

	got := ProfileContext(`Archive/backups/UserProfiles/Alice/.aws/config`)
	want := "archive/backups/userprofiles/alice"
	if got != want {
		t.Fatalf("expected profile context %q, got %q", want, got)
	}
}
