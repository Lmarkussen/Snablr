package credentialanalysis

import (
	"strings"
	"testing"
)

func TestHarvestSCCMStructuredCredentials(t *testing.T) {
	ini := Harvest(HarvestInput{Content: []byte("OSDJoinAccount=SYNTHETIC\\join\nOSDJoinPassword=Synthetic-Join-482!\nOSDLocalAdminPassword=Synthetic-Admin-482!\n"), Path: "task-sequence.ini"})
	if len(ini) != 2 {
		t.Fatalf("candidate count = %d, want 2: %#v", len(ini), ini)
	}
	seen := map[string]Candidate{}
	for _, candidate := range ini {
		seen[candidate.Value] = candidate
	}
	if seen["Synthetic-Join-482!"].Verification != Confirmed || seen["Synthetic-Join-482!"].Identity != `SYNTHETIC\join` {
		t.Fatalf("join credential pairing = %#v", seen["Synthetic-Join-482!"])
	}
	if seen["Synthetic-Admin-482!"].Identity != "" || seen["Synthetic-Admin-482!"].Verification != Review {
		t.Fatalf("local-admin credential was paired with unrelated account: %#v", seen["Synthetic-Admin-482!"])
	}
}

func TestHarvestSCCMXMLPairsOnlyWithinStep(t *testing.T) {
	content := `<sequence><step><variable name="OSDJoinAccount" value="SYNTHETIC\xml-join"/><variable name="OSDJoinPassword" value="Synthetic-XML-482!"/></step><step><variable name="OSDJoinPassword" value="Synthetic-Unpaired-482!"/></step></sequence>`
	candidates := Harvest(HarvestInput{Content: []byte(content), Path: "task-sequence.xml"})
	var paired, unpaired *Candidate
	for index := range candidates {
		switch candidates[index].Value {
		case "Synthetic-XML-482!":
			paired = &candidates[index]
		case "Synthetic-Unpaired-482!":
			unpaired = &candidates[index]
		}
	}
	if paired == nil || paired.Verification != Confirmed || paired.Identity != `SYNTHETIC\xml-join` {
		t.Fatalf("XML pair missing or incorrect: %#v", paired)
	}
	if unpaired == nil || unpaired.Verification != Review || unpaired.Identity != "" {
		t.Fatalf("cross-step password was promoted: %#v", unpaired)
	}
	for _, candidate := range candidates {
		if candidate.Value == "Synthetic-XML-482!" && candidate.ValidationBasis == "structured XML object" {
			t.Fatalf("generic XML candidate duplicated the scoped SCCM record: %#v", candidate)
		}
	}
}

func TestHarvestSCCMJSONPairsMatchingAccountOnly(t *testing.T) {
	content := `{"OSDJoinAccount":"SYNTHETIC\\json-join","OSDJoinPassword":"Synthetic-JSON-482!","OSDLocalAdminPassword":"Synthetic-JSON-Admin-482!"}`
	candidates := Harvest(HarvestInput{Content: []byte(content), Path: "task-sequence.json"})
	for _, candidate := range candidates {
		switch candidate.Value {
		case "Synthetic-JSON-482!":
			if candidate.Verification != Confirmed || candidate.Identity != `SYNTHETIC\json-join` {
				t.Fatalf("JSON join pairing = %#v", candidate)
			}
		case "Synthetic-JSON-Admin-482!":
			if candidate.Identity != "" {
				t.Fatalf("JSON local-admin password used unrelated join account: %#v", candidate)
			}
		}
	}
}

func TestHarvestSCCMRejectsUnresolvedValues(t *testing.T) {
	content := strings.Join([]string{
		"OSDJoinAccount=SYNTHETIC\\reference-only",
		"OSDJoinPassword=<PASSWORD>",
		"OSDLocalAdminPassword=********",
		"EncryptedNetworkAccessAccount=BASE64-ENCODED-SYNTHETIC-BLOB",
	}, "\n")
	for _, candidate := range Harvest(HarvestInput{Content: []byte(content), Path: "negative.ini"}) {
		if strings.Contains(candidate.Value, "PASSWORD") || strings.Contains(candidate.Value, "BASE64") || candidate.Value == "********" {
			t.Fatalf("unresolved SCCM value harvested: %#v", candidate)
		}
	}
}
