package browsercredinspect

import "testing"

func TestInspectMetadataMatchesFirefoxArtifacts(t *testing.T) {
	t.Parallel()

	inspector := New()
	matches := inspector.InspectMetadata(Candidate{
		FilePath: `Users\Alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd.default-release\logins.json`,
		Name:     "logins.json",
	})
	if len(matches) != 1 {
		t.Fatalf("expected one match, got %#v", matches)
	}
	if matches[0].ID != "browsercredinspect.firefox.logins" {
		t.Fatalf("unexpected match: %#v", matches[0])
	}
}

func TestInspectMetadataMatchesChromiumArtifactsCaseInsensitive(t *testing.T) {
	t.Parallel()

	inspector := New()
	matches := inspector.InspectMetadata(Candidate{
		FilePath: `Archive/ProfileCopies/Bob/AppData/Local/Google/Chrome/User Data/Default/Login Data`,
		Name:     "Login Data",
	})
	if len(matches) != 1 {
		t.Fatalf("expected one match, got %#v", matches)
	}
	if matches[0].ID != "browsercredinspect.chromium.login_data" {
		t.Fatalf("unexpected match: %#v", matches[0])
	}
}

func TestInspectMetadataIgnoresNearMissArtifacts(t *testing.T) {
	t.Parallel()

	inspector := New()
	matches := inspector.InspectMetadata(Candidate{
		FilePath: `Users/Alice/AppData/Roaming/Mozilla/Firefox/Profiles/abcd.default-release/logins.json.bak`,
		Name:     "logins.json.bak",
	})
	if len(matches) != 0 {
		t.Fatalf("expected no match for near-miss artifact, got %#v", matches)
	}
}

func TestProfileContextNormalizesBrowserProfiles(t *testing.T) {
	t.Parallel()

	got := ProfileContext(`Archive\ProfileCopies\Bob\AppData\Local\Google\Chrome\User Data\Default\Login Data`)
	want := "archive/profilecopies/bob/appdata/local/google/chrome/user data/default"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
