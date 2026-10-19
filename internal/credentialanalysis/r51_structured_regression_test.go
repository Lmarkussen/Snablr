package credentialanalysis

import "testing"

func TestHarvestR51AccountSecretScopes(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		content      string
		wantUser     string
		wantPassword string
	}{
		{"json object", "fixture.json", `{"services":[{"account":"svc-json","secret":"JsonPass!"}]}`, "svc-json", "JsonPass!"},
		{"csv record", "fixture.csv", "account,secret,target\nsvc-csv,CsvPass!,db", "svc-csv", "CsvPass!"},
		{"html form", "fixture.html", `<form><input name="user" value="svc-html"><input name="password" value="HtmlPass!"></form>`, "svc-html", "HtmlPass!"},
		{"powershell hashtable", "fixture.ps1", `$params = @{ User = 'svc-ps'; Password = 'PowerShellPass!'; Target = 'db' }`, "svc-ps", "PowerShellPass!"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidates := Harvest(HarvestInput{Content: []byte(test.content), Path: test.path})
			for _, candidate := range candidates {
				if candidate.Identity == test.wantUser && candidate.Value == test.wantPassword && candidate.Verification == Confirmed {
					return
				}
			}
			t.Fatalf("missing confirmed pair %q/%q in %#v", test.wantUser, test.wantPassword, candidates)
		})
	}
}

func TestHarvestR51PrefixedAssignmentsDoNotCrossPair(t *testing.T) {
	content := "[integration]\nusername=primary\npassword=PrimaryPass!\nsecondary_username=secondary\nsecondary_password=SecondaryPass!\n"
	candidates := Harvest(HarvestInput{Content: []byte(content), Path: "fixture.conf"})
	want := map[string]string{"primary": "PrimaryPass!", "secondary": "SecondaryPass!"}
	for _, candidate := range candidates {
		if candidate.Verification == Confirmed && want[candidate.Identity] == candidate.Value {
			delete(want, candidate.Identity)
		}
		if candidate.Identity == "primary" && candidate.Value == "SecondaryPass!" {
			t.Fatal("cross-scope pairing was produced")
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing scoped pairs: %#v; candidates=%#v", want, candidates)
	}
}

func TestHarvestOfficeSectionKeepsCompoundPasswordWithAccount(t *testing.T) {
	input := Harvest(HarvestInput{
		Path:    "word/document.xml",
		Content: []byte("[word body block 1]\naccount: office-user\nuser_password: Office-Pass!\n"),
	})
	if !hasCandidatePayload(input, Confirmed, "Office-Pass!", "office-user", "") {
		t.Fatalf("office section pair was not confirmed: %#v", input)
	}
}

func TestHarvestOfficeSectionDoesNotCrossExplicitScopes(t *testing.T) {
	input := Harvest(HarvestInput{
		Path:    "worksheet.xml",
		Content: []byte("[worksheet record 1]\naccount=alice\nuser_password=Alice-Pass!\nalternate_password=Other-Pass!\n"),
	})
	for _, candidate := range input {
		if candidate.Verification == Confirmed && candidate.Identity == "alice" && candidate.Value == "Other-Pass!" {
			t.Fatalf("office section produced a cross-scope pair: %#v", input)
		}
	}
}

func TestR51JSONEscapedDomainIdentity(t *testing.T) {
	input := Harvest(HarvestInput{Path: "fixture.py", Content: []byte(`client = {"username": "SYNTHETIC\\local261", "password": "Harbor-782-Delta!"}`)})
	for _, candidate := range input {
		if candidate.Identity == `SYNTHETIC\local261` && candidate.Value == "Harbor-782-Delta!" && candidate.Verification == Confirmed {
			return
		}
	}
	t.Fatalf("escaped identity was not decoded: %#v", input)
}

func TestR51PropertiesSectionsDoNotCrossPair(t *testing.T) {
	input := Harvest(HarvestInput{Path: "fixture.properties", Content: []byte("[accounts]\nuser=SYNTHETIC\\local312\n\n[defaults]\npassword=Copper-377-North!\n")})
	for _, candidate := range input {
		if candidate.Identity == `SYNTHETIC\local312` && candidate.Value == "Copper-377-North!" && candidate.Verification == Confirmed {
			t.Fatalf("cross-section pair was confirmed: %#v", candidate)
		}
	}
}
