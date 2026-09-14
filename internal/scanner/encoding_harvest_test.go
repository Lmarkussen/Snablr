package scanner

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"

	"snablr/internal/credentialanalysis"
	"snablr/internal/rules"
	"snablr/pkg/logx"
)

func TestEngineHarvestsUTF16LECustomSettingsAndUnattend(t *testing.T) {
	collector := &recordingCandidateSink{}
	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	engine.SetCredentialCandidateSink(collector)

	custom := utf16ScannerBytes("[Default]\nAdminUser=Administrator\nAdminDomain=CONTOSO\nAdminPassword=Engine-Utf16LE-CustomSettings-Test!\n", binary.LittleEndian, false)
	customEval := engine.EvaluateContext(context.Background(), FileMetadata{FilePath: "CustomSettings.ini", Name: "CustomSettings.ini", Extension: ".ini", Size: int64(len(custom))}, custom)
	if customEval.Skipped {
		t.Fatalf("CustomSettings unexpectedly skipped: %s", customEval.SkipReason)
	}
	if !hasCandidateValue(collector.candidates, "Engine-Utf16LE-CustomSettings-Test!", "Administrator", "CONTOSO", credentialanalysis.Confirmed) {
		t.Fatalf("UTF-16LE CustomSettings candidate missing: %#v", collector.candidates)
	}

	collector = &recordingCandidateSink{}
	engine.SetCredentialCandidateSink(collector)
	unattend := utf16ScannerBytes(`<?xml version="1.0" encoding="utf-16"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-Shell-Setup">
      <UserAccounts>
        <AdministratorPassword>
          <Value>Engine-Utf16LE-Unattend-Test!</Value>
          <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
    </component>
  </settings>
</unattend>`, binary.LittleEndian, false)
	unattendEval := engine.EvaluateContext(context.Background(), FileMetadata{FilePath: "unattend.xml", Name: "unattend.xml", Extension: ".xml", Size: int64(len(unattend))}, unattend)
	if unattendEval.Skipped {
		t.Fatalf("unattend unexpectedly skipped: %s", unattendEval.SkipReason)
	}
	if !hasCandidateValue(collector.candidates, "Engine-Utf16LE-Unattend-Test!", "Administrator", "", credentialanalysis.Confirmed) {
		t.Fatalf("UTF-16LE unattend candidate missing: %#v", collector.candidates)
	}
}

func utf16ScannerBytes(text string, order binary.ByteOrder, withBOM bool) []byte {
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
