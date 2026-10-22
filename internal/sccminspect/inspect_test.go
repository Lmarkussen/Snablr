package sccminspect

import "testing"

func TestInspectScopedJSONRecords(t *testing.T) {
	content := []byte(`{"records":[{"sccmType":"client","siteCode":"ABC","managementPoints":["https://mp-a","https://mp-b"]},{"sccmType":"deployment","packageId":"PKG001","collectionId":"COL001"}]}`)
	got := New().InspectContent(Candidate{Name: "sccm.json", Extension: ".json", Size: int64(len(content))}, content)
	if len(got) != 3 || got[0].ID != "sccminspect.client.management_point" || got[2].ID != "sccminspect.deployment.reference" {
		t.Fatalf("unexpected JSON observations: %#v", got)
	}
	if got[0].MatchedText != string(content) || got[0].ObservationKey == got[1].ObservationKey {
		t.Fatalf("JSON evidence or scope identity was lost: %#v", got)
	}
	if got[0].SignalType != "content" || got[0].Confidence != "medium" || got[0].ValidationBasis == "" {
		t.Fatalf("synthetic SCCM contract was overstated: %#v", got[0])
	}
}

func TestInspectXMLAndINIAndRejectGenericLookalikes(t *testing.T) {
	xml := []byte(`<SCCMClient><SiteCode>ABC</SiteCode><ManagementPoints><ManagementPoint>mp-a</ManagementPoint><ManagementPoint>mp-b</ManagementPoint></ManagementPoints></SCCMClient>`)
	if got := New().InspectContent(Candidate{Name: "client.xml", Extension: ".xml", Size: int64(len(xml))}, xml); len(got) != 2 {
		t.Fatalf("unexpected XML observations: %#v", got)
	}
	ini := []byte("[SCCM.Client]\nSiteCode=ABC\nManagementPoint=mp-a\n\n[SCCM.Deployment.one]\nPackageID=PKG001\nCollectionID=COL001\n")
	if got := New().InspectContent(Candidate{Name: "client.ini", Extension: ".ini", Size: int64(len(ini))}, ini); len(got) != 2 {
		t.Fatalf("unexpected INI observations: %#v", got)
	}
	generic := []byte(`{"siteCode":"ABC","managementPoint":"https://not-sccm"}`)
	if got := New().InspectContent(Candidate{Name: "notes.json", Extension: ".json", Size: int64(len(generic))}, generic); len(got) != 0 {
		t.Fatalf("generic lookalike was promoted: %#v", got)
	}
}

func TestRejectMalformedAndInvalidSiteCodes(t *testing.T) {
	content := []byte(`{"sccmType":"client","siteCode":"A1","managementPoints":["mp"]}`)
	if got := New().InspectContent(Candidate{Name: "sccm.json", Extension: ".json", Size: int64(len(content))}, content); len(got) != 0 {
		t.Fatalf("invalid site code was accepted: %#v", got)
	}
	malformed := []byte(`<SCCMClient><SiteCode>ABC</SiteCode>`)
	if got := New().InspectContent(Candidate{Name: "sccm.xml", Extension: ".xml", Size: int64(len(malformed))}, malformed); len(got) != 0 {
		t.Fatalf("malformed SCCM XML was accepted: %#v", got)
	}
}
