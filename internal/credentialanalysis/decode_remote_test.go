package credentialanalysis

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// Vectors produced independently (pycryptodome) with the published keys:
// VNC DES key e84ad660c4721ae0, TeamViewer AES-128-CBC key/IV from
// CVE-2019-18988. All plaintexts are synthetic.
const (
	vncFull         = "0b6bfe063f5c12d6"                                                 // "Vnc8Chr!"
	vncShort        = "fe002bb2deff7c53"                                                 // "vw2026"
	teamViewerOpts  = "eea2102d7ec76a797e8b6d4baaaa58558f094803b6fbe7cacafd14ec05959bd4" // "TeamV-Unatt-2026"
	teamViewerProxy = "6a2ff0a727bfe3f58f4a612302ec48e6a52448abff1bcc4a20b887362f5c5d6a" // "Proxy-Pass-77"
)

func regHex(hexValue string) string {
	var parts []string
	for i := 0; i+1 < len(hexValue); i += 2 {
		parts = append(parts, hexValue[i:i+2])
	}
	// regedit wraps long values with a trailing backslash.
	out := "hex:" + strings.Join(parts[:len(parts)/2], ",")
	if rest := parts[len(parts)/2:]; len(rest) > 0 {
		out += ",\\\r\n  " + strings.Join(rest, ",")
	}
	return out
}

// regeditUTF16 encodes text as regedit writes version 5.00 exports:
// UTF-16LE with a byte order mark.
func regeditUTF16(text string) []byte {
	out := []byte{0xff, 0xfe}
	for _, unit := range utf16.Encode([]rune(text)) {
		out = binary.LittleEndian.AppendUint16(out, unit)
	}
	return out
}

func confirmedValues(candidates []Candidate) map[string]Candidate {
	out := map[string]Candidate{}
	for _, c := range candidates {
		if c.Verification == Confirmed {
			out[c.Value] = c
		}
	}
	return out
}

func TestVNCAndTeamViewerPasswordsDecode(t *testing.T) {
	ini := "[ultravnc]\r\npasswd=" + strings.ToUpper(vncFull) + "AB\r\npasswd2=" + vncShort + "00\r\n[admin]\r\nUseRegistry=0\r\n"
	got := confirmedValues(Harvest(HarvestInput{Path: "Program Files/uvnc bvba/UltraVNC/ultravnc.ini", Content: []byte(ini)}))
	if _, ok := got["Vnc8Chr!"]; !ok {
		t.Errorf("UltraVNC passwd not decoded: %v", got)
	}
	if _, ok := got["vw2026"]; !ok {
		t.Errorf("UltraVNC view-only passwd2 not decoded: %v", got)
	}

	reg := "Windows Registry Editor Version 5.00\r\n\r\n" +
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\TightVNC\\Server]\r\n\"Password\"=" + regHex(vncFull) + "\r\n\"PasswordViewOnly\"=" + regHex(vncShort) + "\r\n\r\n" +
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\TeamViewer]\r\n\"ClientID\"=dword:4d2a1f00\r\n\"OptionsPasswordAES\"=" + regHex(teamViewerOpts) + "\r\n" +
		"\"ProxyUsername\"=\"CORP\\\\proxy-svc\"\r\n\"ProxyPasswordAES\"=" + regHex(teamViewerProxy) + "\r\n"
	for name, content := range map[string][]byte{"ascii": []byte(reg), "utf-16": regeditUTF16(reg)} {
		got := confirmedValues(Harvest(HarvestInput{Path: "IT/exports/remote-tools.reg", Content: content}))
		for _, want := range []string{"Vnc8Chr!", "vw2026", "TeamV-Unatt-2026", "Proxy-Pass-77"} {
			if _, ok := got[want]; !ok {
				t.Errorf("%s: %q not decoded: %v", name, want, got)
			}
		}
		if proxy := got["Proxy-Pass-77"]; proxy.Identity != `CORP\proxy-svc` {
			t.Errorf("%s: proxy password not paired with its user: %+v", name, proxy)
		}
	}
}

func TestRemoteStoreDecodersRejectOtherValues(t *testing.T) {
	if _, ok := DecodeVNCPassword("zz6bfe063f5c12d6"); ok {
		t.Error("non-hex VNC value decoded")
	}
	if _, ok := DecodeVNCPassword("0b6bfe06"); ok {
		t.Error("short VNC value decoded")
	}
	if _, ok := DecodeTeamViewerPassword([]byte("not-a-block")); ok {
		t.Error("TeamViewer value of wrong length decoded")
	}
	// A Password value outside a VNC key is not a VNC password.
	reg := "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\SomeApp]\r\n\"Password\"=" + regHex(vncFull) + "\r\n"
	if got := confirmedValues(Harvest(HarvestInput{Path: "exports/app.reg", Content: []byte(reg)})); len(got) > 0 {
		t.Errorf("non-VNC registry value decoded as VNC: %v", got)
	}
}

func TestMachineKeyIsReported(t *testing.T) {
	validation := strings.Repeat("A1B2C3D4E5F60718", 8)
	decryption := strings.Repeat("0F1E2D3C4B5A6978", 2)
	config := `<?xml version="1.0"?>
<configuration>
  <system.web>
    <machineKey validationKey="` + validation + `" decryptionKey="` + decryption + `" validation="HMACSHA256" decryption="AES" />
  </system.web>
</configuration>`
	var key *Candidate
	for _, c := range Harvest(HarvestInput{Path: "inetpub/wwwroot/portal/web.config", Content: []byte(config)}) {
		if c.CredentialType == "machine_key" {
			c := c
			key = &c
		}
	}
	if key == nil || key.Verification != Confirmed {
		t.Fatalf("machineKey not reported as confirmed: %+v", key)
	}
	for _, want := range []string{"validationKey=" + validation, "validation=HMACSHA256", "decryptionKey=" + decryption, "decryption=AES"} {
		if !strings.Contains(key.Value, want) {
			t.Errorf("machine key value lacks %q: %s", want, key.Value)
		}
	}

	for _, attrs := range []string{
		`validationKey="AutoGenerate,IsolateApps" decryptionKey="AutoGenerate,IsolateApps"`,
		`validationKey="[your validation key]"`,
		`validation="SHA1"`,
	} {
		config := `<configuration><system.web><machineKey ` + attrs + ` /></system.web></configuration>`
		for _, c := range Harvest(HarvestInput{Path: "web.config", Content: []byte(config)}) {
			if c.CredentialType == "machine_key" {
				t.Errorf("%s reported as a machine key: %+v", attrs, c)
			}
		}
	}
}
