package windowsinspect

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestInspectUnattendAndTaskScheduler(t *testing.T) {
	inspector := New()
	unattend := []byte(`<unattend><settings pass="specialize"><component name="Microsoft-Windows-Shell-Setup"><UserAccounts><AdministratorPassword><Value>Synthetic!</Value></AdministratorPassword></UserAccounts></component></settings></unattend>`)
	if got := inspector.InspectContent(Candidate{Name: "unattend.xml", Extension: ".xml", Size: int64(len(unattend))}, unattend); len(got) != 1 || got[0].ID != "windowsinspect.unattend.structured" {
		t.Fatalf("unattend was not structurally recognized: %#v", got)
	}
	task := []byte(`<Task><RegistrationInfo><URI>\\Synthetic\Task</URI></RegistrationInfo><Principals><Principal id="Author"/></Principals><Triggers><LogonTrigger/></Triggers><Actions><Exec><Command>cmd.exe</Command></Exec></Actions></Task>`)
	if got := inspector.InspectContent(Candidate{Name: "task.xml", Extension: ".xml", Size: int64(len(task))}, task); len(got) != 1 || got[0].ID != "windowsinspect.scheduled_task.structured" {
		t.Fatalf("scheduled task was not structurally recognized: %#v", got)
	}
}

func TestInspectGPPItemsAndRejectGenericCpassword(t *testing.T) {
	inspector := New()
	gpp := []byte(`<Groups><User name="synthetic"><Properties userName="svc" cpassword="ENCODED"/></User></Groups>`)
	got := inspector.InspectContent(Candidate{Name: "Groups.xml", Extension: ".xml", Size: int64(len(gpp))}, gpp)
	if len(got) != 1 || got[0].ID != "windowsinspect.gpp.groups" || got[0].MatchedText != string(gpp) {
		t.Fatalf("GPP structure/evidence mismatch: %#v", got)
	}
	generic := []byte(`<root><item cpassword="not-a-gpp-document"/></root>`)
	if got := inspector.InspectContent(Candidate{Name: "notes.xml", Extension: ".xml", Size: int64(len(generic))}, generic); len(got) != 0 {
		t.Fatalf("generic cpassword was promoted: %#v", got)
	}
}

func TestInspectGPPDrivesAndRegistryItems(t *testing.T) {
	inspector := New()
	for _, root := range []string{"Drives", "Registry"} {
		content := []byte("<" + root + "><" + strings.TrimSuffix(root, "s") + " name=\"one\"/><" + strings.TrimSuffix(root, "s") + " name=\"two\"/></" + root + ">")
		got := inspector.InspectContent(Candidate{Name: root + ".xml", Extension: ".xml", Size: int64(len(content))}, content)
		if len(got) != 2 {
			t.Fatalf("%s items were not kept separate: %#v", root, got)
		}
		if got[0].ObservationKey == got[1].ObservationKey {
			t.Fatalf("%s item observation keys collided: %#v", root, got)
		}
	}
}

func TestInspectRegistryExportAndRejectMalformed(t *testing.T) {
	inspector := New()
	reg := []byte("Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\Software\\Synthetic]\r\n\"SiteCode\"=\"ABC\"\r\n")
	got := inspector.InspectContent(Candidate{Name: "export.reg", Extension: ".reg", Size: int64(len(reg))}, reg)
	if len(got) != 1 || got[0].ID != "windowsinspect.registry_export.structured" || got[0].MatchedText != string(reg) {
		t.Fatalf("registry export mismatch: %#v", got)
	}
	malformed := []byte("Windows Registry Editor Version 5.00\nnot a key section")
	if got := inspector.InspectContent(Candidate{Name: "export.reg", Extension: ".reg", Size: int64(len(malformed))}, malformed); len(got) != 0 {
		t.Fatalf("malformed registry export was accepted: %#v", got)
	}
}

func TestInspectUTF16AndContentEligibility(t *testing.T) {
	text := `<unattend><settings><component name="x"/></settings></unattend>`
	encoded := append([]byte{0xFF, 0xFE}, utf16Bytes(text, binary.LittleEndian)...)
	got := New().InspectContent(Candidate{Name: "extensionless", Size: int64(len(encoded))}, encoded)
	if len(got) != 1 || got[0].ID != "windowsinspect.unattend.structured" {
		t.Fatalf("UTF-16 unattended XML was not recognized: %#v", got)
	}
	if !New().NeedsContent(Candidate{Name: "export.reg", Extension: ".reg", Size: 100}) || !New().NeedsContent(Candidate{Name: "extensionless", Size: 100}) {
		t.Fatal("eligible Windows files were not marked for content inspection")
	}
}

func utf16Bytes(text string, order binary.ByteOrder) []byte {
	values := utf16.Encode([]rune(text))
	result := make([]byte, len(values)*2)
	for index, value := range values {
		order.PutUint16(result[index*2:], value)
	}
	return result
}
