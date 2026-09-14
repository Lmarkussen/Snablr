package credentialanalysis

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestHarvestDecodesUTF8BOMCustomSettings(t *testing.T) {
	content := append([]byte{0xEF, 0xBB, 0xBF}, []byte("[Default]\nAdminUser=Administrator\nAdminDomain=CONTOSO\nAdminPassword=Utf8BOM-CustomSettings-Test!\n")...)
	got := Harvest(HarvestInput{Content: content, Path: "CustomSettings.ini"})
	if !hasCandidate(got, Confirmed, "Utf8BOM-CustomSettings-Test!") {
		t.Fatalf("UTF-8 BOM CustomSettings credential was not harvested: %#v", got)
	}
}

func TestHarvestDecodesUTF16LEBOMCustomSettings(t *testing.T) {
	content := utf16BytesWithBOM("[Default]\nAdminUser=Administrator\nAdminDomain=CONTOSO\nAdminPassword=Utf16LE-CustomSettings-Test!\n", binary.LittleEndian, true)
	got := Harvest(HarvestInput{Content: content, Path: "CustomSettings.ini"})
	if !hasCandidate(got, Confirmed, "Utf16LE-CustomSettings-Test!") {
		t.Fatalf("UTF-16LE BOM CustomSettings credential was not harvested: %#v", got)
	}
}

func TestHarvestDecodesUTF16LEWithoutBOMCustomSettings(t *testing.T) {
	content := utf16BytesWithBOM("[Default]\nAdminUser=Administrator\nAdminDomain=CONTOSO\nAdminPassword=Utf16LE-NoBOM-CustomSettings-Test!\n", binary.LittleEndian, false)
	got := Harvest(HarvestInput{Content: content, Path: "CustomSettings.ini"})
	if !hasCandidate(got, Confirmed, "Utf16LE-NoBOM-CustomSettings-Test!") {
		t.Fatalf("UTF-16LE no-BOM CustomSettings credential was not harvested: %#v", got)
	}
}

func TestHarvestDecodesUTF16BEBOMCustomSettings(t *testing.T) {
	content := utf16BytesWithBOM("[Default]\nAdminUser=Administrator\nAdminDomain=CONTOSO\nAdminPassword=Utf16BE-CustomSettings-Test!\n", binary.BigEndian, true)
	got := Harvest(HarvestInput{Content: content, Path: "CustomSettings.ini"})
	if !hasCandidate(got, Confirmed, "Utf16BE-CustomSettings-Test!") {
		t.Fatalf("UTF-16BE BOM CustomSettings credential was not harvested: %#v", got)
	}
}

func TestHarvestDecodesUTF16LEUnattendXML(t *testing.T) {
	xmlText := `<?xml version="1.0" encoding="utf-16"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-Shell-Setup">
      <UserAccounts>
        <AdministratorPassword>
          <Value>Utf16-Unattend-Admin-Test!</Value>
          <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <AutoLogon>
        <Password>
          <Value>Utf16-Unattend-AutoLogon-Test!</Value>
          <PlainText>true</PlainText>
        </Password>
        <Username>Administrator</Username>
        <Domain>CONTOSO</Domain>
        <Enabled>true</Enabled>
      </AutoLogon>
    </component>
    <component name="Microsoft-Windows-UnattendedJoin">
      <Identification>
        <Credentials>
          <Domain>CONTOSO</Domain>
          <Username>deploysvc</Username>
          <Password>Utf16-Unattend-Credentials-Test!</Password>
        </Credentials>
      </Identification>
    </component>
  </settings>
</unattend>`
	content := utf16BytesWithBOM(xmlText, binary.LittleEndian, true)
	got := Harvest(HarvestInput{Content: content, Path: "unattend.xml"})
	for _, value := range []string{
		"Utf16-Unattend-Admin-Test!",
		"Utf16-Unattend-AutoLogon-Test!",
		"Utf16-Unattend-Credentials-Test!",
	} {
		if !hasCandidate(got, Confirmed, value) {
			t.Fatalf("UTF-16LE unattend credential %q was not harvested: %#v", value, got)
		}
	}
}

func TestHarvestDecodesUTF16BEUnattendXML(t *testing.T) {
	xmlText := `<?xml version="1.0" encoding="utf-16"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-Shell-Setup">
      <UserAccounts>
        <AdministratorPassword>
          <Value>Utf16BE-Unattend-Admin-Test!</Value>
          <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
    </component>
  </settings>
</unattend>`
	content := utf16BytesWithBOM(xmlText, binary.BigEndian, true)
	got := Harvest(HarvestInput{Content: content, Path: "unattend.xml"})
	if !hasCandidate(got, Confirmed, "Utf16BE-Unattend-Admin-Test!") {
		t.Fatalf("UTF-16BE unattend credential was not harvested: %#v", got)
	}
}

func utf16BytesWithBOM(text string, order binary.ByteOrder, withBOM bool) []byte {
	encoded := utf16.Encode([]rune(strings.ReplaceAll(text, "\r\n", "\n")))
	out := make([]byte, 0, len(encoded)*2+2)
	if withBOM {
		if order == binary.LittleEndian {
			out = append(out, 0xFF, 0xFE)
		} else {
			out = append(out, 0xFE, 0xFF)
		}
	}
	buf := make([]byte, 2)
	for _, value := range encoded {
		order.PutUint16(buf, value)
		out = append(out, buf...)
	}
	return out
}
