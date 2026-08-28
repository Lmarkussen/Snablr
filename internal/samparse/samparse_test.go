package samparse

import (
	"bytes"
	"errors"
	"testing"

	"snablr/internal/registryhive"
	"snablr/internal/registryhive/testfixture"
	"snablr/internal/systemkey"
)

func bootKeyForFixture(t *testing.T) [16]byte {
	t.Helper()
	current := uint32(1)
	system := testfixture.Build(testfixture.Spec{
		Current: &current, IncludeSelect: true, IncludeCurrent: true,
		IncludeControl: true, IncludeLSA: true,
		Fragments: map[string]string{"JD": "00112233", "Skew1": "22334455", "GBG": "66778899", "Data": "aabbccdd"},
	})
	hive, err := registryhive.Open(bytes.NewReader(system), int64(len(system)), registryhive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := systemkey.Derive(hive)
	if err != nil {
		t.Fatal(err)
	}
	return result.BootKey
}

func ntVector(hexBytes ...byte) [16]byte { var out [16]byte; copy(out[:], hexBytes); return out }

func parseFixture(t *testing.T, spec testfixture.SAMSpec) Result {
	t.Helper()
	b := testfixture.BuildSAM(spec)
	hive, err := registryhive.Open(bytes.NewReader(b), int64(len(b)), registryhive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Parse(Inputs{SAM: hive, BootKey: spec.BootKey})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestParseLegacyAccountsEndToEnd(t *testing.T) {
	boot := bootKeyForFixture(t)
	passwordHash := ntVector(0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17, 0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c)
	disabled := false
	result := parseFixture(t, testfixture.SAMSpec{BootKey: boot, KeyRevision: 1, IncludeDomain: true, Accounts: []testfixture.SAMAccount{
		{RID: 1001, Username: "svc_test", NTHash: passwordHash, HashRevision: 1},
		{RID: 500, Username: "localadmin", NTHash: passwordHash, HashRevision: 1, Enabled: &disabled},
	}})
	if result.SAMRevision != 3 || len(result.Accounts) != 2 || len(result.Errors) != 0 {
		t.Fatalf("unexpected result shape: revision=%d accounts=%d errors=%d", result.SAMRevision, len(result.Accounts), len(result.Errors))
	}
	if result.Accounts[0].RID != 500 || result.Accounts[1].RID != 1001 {
		t.Fatalf("accounts not RID-sorted")
	}
	for _, account := range result.Accounts {
		if account.Username == "" || account.NT.Status != HashRecovered || account.NT.Value != passwordHash {
			t.Fatalf("account recovery failed for RID %d", account.RID)
		}
		if account.LM.Status != HashAbsent {
			t.Fatalf("LM unexpectedly present")
		}
	}
	if result.Accounts[0].Enabled == nil || *result.Accounts[0].Enabled {
		t.Fatalf("disabled state not preserved")
	}
}

func TestParseAESAccountsEndToEnd(t *testing.T) {
	boot := bootKeyForFixture(t)
	hash := ntVector(0x2b, 0x57, 0x6a, 0xcb, 0xe6, 0xbc, 0xfd, 0xa7, 0x29, 0x4d, 0x6b, 0xd1, 0x80, 0x41, 0xb8, 0xfe)
	result := parseFixture(t, testfixture.SAMSpec{BootKey: boot, KeyRevision: 2, IncludeDomain: true, Accounts: []testfixture.SAMAccount{{RID: 1100, Username: "unicode_тест", NTHash: hash, HashRevision: 2}}})
	if len(result.Accounts) != 1 || result.Accounts[0].Username != "unicode_тест" || result.Accounts[0].NT.Status != HashRecovered || result.Accounts[0].NT.Value != hash {
		t.Fatalf("AES account recovery failed")
	}
}

func TestParsePartialAccountFailure(t *testing.T) {
	boot := bootKeyForFixture(t)
	hash := ntVector(0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17, 0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c)
	b := testfixture.BuildSAM(testfixture.SAMSpec{BootKey: boot, KeyRevision: 1, IncludeDomain: true, Accounts: []testfixture.SAMAccount{{RID: 1001, Username: "good", NTHash: hash, HashRevision: 1}, {RID: 1002, Username: "bad", NTHash: hash, HashRevision: 99}}})
	hive, err := registryhive.Open(bytes.NewReader(b), int64(len(b)), registryhive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Parse(Inputs{SAM: hive, BootKey: boot})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Accounts) != 2 || result.Accounts[1].NT.Status != HashUnsupported || len(result.Errors) != 0 {
		t.Fatalf("unsupported hash not represented per-account: accounts=%d errors=%d statuses=%v/%v", len(result.Accounts), len(result.Errors), result.Accounts[0].NT.Status, result.Accounts[1].NT.Status)
	}
}

func TestParseDomainFailures(t *testing.T) {
	boot := bootKeyForFixture(t)
	cases := []struct {
		name string
		spec testfixture.SAMSpec
		want error
	}{
		{"missing-domain", testfixture.SAMSpec{BootKey: boot}, ErrMissingDomain},
		{"unsupported-key", testfixture.SAMSpec{BootKey: boot, KeyRevision: 9, IncludeDomain: true}, ErrUnsupportedRevision},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := testfixture.BuildSAM(tc.spec)
			hive, err := registryhive.Open(bytes.NewReader(b), int64(len(b)), registryhive.Options{})
			if err != nil {
				t.Fatal(err)
			}
			_, err = Parse(Inputs{SAM: hive, BootKey: boot})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want %v", err, tc.want)
			}
		})
	}
}

func TestSAMKeyRejectsWrongBootKeyAndMalformedRecords(t *testing.T) {
	boot := bootKeyForFixture(t)
	fixture := testfixture.BuildSAM(testfixture.SAMSpec{BootKey: boot, KeyRevision: 1, IncludeDomain: true})
	hive, err := registryhive.Open(bytes.NewReader(fixture), int64(len(fixture)), registryhive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	account, err := hive.OpenKey(`Domains\Account`)
	if err != nil {
		t.Fatal(err)
	}
	f, err := account.Value("F")
	if err != nil {
		t.Fatal(err)
	}
	var wrong [16]byte
	_, _, err = deriveSAMKey(f.Bytes(), wrong)
	if !errors.Is(err, ErrInvalidChecksum) {
		t.Fatalf("wrong boot key error=%v", err)
	}
	if _, _, err = deriveSAMKey([]byte{3}, boot); !errors.Is(err, ErrMalformedRecord) {
		t.Fatalf("short F error=%v", err)
	}

	if status, _ := decryptHash([]byte{0, 0, 99, 0}, 500, [16]byte{}, []byte("NTPASSWORD\x00")); status != HashUnsupported {
		t.Fatalf("unsupported hash status=%v", status)
	}
	if status, _ := decryptHash([]byte{0, 0, 1}, 500, [16]byte{}, []byte("NTPASSWORD\x00")); status != HashMalformed {
		t.Fatalf("truncated hash status=%v", status)
	}
}

func TestVFieldRejectsOutOfRangeAndInvalidUTF16(t *testing.T) {
	data := make([]byte, 0xcc)
	data[0x0c] = 0xff
	data[0x10] = 0xff
	if _, err := vField(data, 0x0c, 0xcc, true); !errors.Is(err, ErrMalformedRecord) {
		t.Fatalf("out-of-range V field error=%v", err)
	}
	data = make([]byte, 0xce)
	data[0x10] = 1
	if _, err := vField(data, 0x0c, 0xcc, true); !errors.Is(err, ErrMalformedRecord) {
		t.Fatalf("odd UTF-16 V field error=%v", err)
	}
}

func TestRIDDESKeysHaveExpectedParity(t *testing.T) {
	keys, ok := ridDESKeys(500)
	if !ok {
		t.Fatal("RID key derivation failed")
	}
	for _, key := range keys {
		for _, b := range key {
			if byteOnes(b)%2 != 1 {
				t.Fatalf("DES key byte has even parity")
			}
		}
	}
}

func TestRIDParsing(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{{"1f4", true}, {"000003e9", true}, {"Names", false}, {"-1", false}, {"0x1f4", false}, {"", false}} {
		_, ok := parseRID(tc.name)
		if ok != tc.ok {
			t.Fatalf("parseRID(%q)=%v", tc.name, ok)
		}
	}
}

func FuzzParse(f *testing.F) {
	var boot [16]byte
	f.Add(testfixture.BuildSAM(testfixture.SAMSpec{BootKey: boot, KeyRevision: 1, IncludeDomain: true}))
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if recover() != nil {
				t.Fatalf("panic")
			}
		}()
		hive, err := registryhive.Open(bytes.NewReader(data), int64(len(data)), registryhive.Options{})
		if err == nil {
			_, _ = Parse(Inputs{SAM: hive, BootKey: boot})
		}
	})
}
