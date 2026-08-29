package securityparse

import (
	"bytes"
	"encoding/json"
	"testing"

	"snablr/internal/registryhive"
	"snablr/internal/registryhive/testfixture"
)

func TestParseModernSecurityFixtureReturnsSafeMetadata(t *testing.T) {
	boot := [16]byte{1, 2, 3, 4}
	lsa := [32]byte{5, 6, 7, 8}
	nlkm := make([]byte, 32)
	for i := range nlkm {
		nlkm[i] = byte(0x30 + i)
	}
	iteration := uint32(4096)
	hiveBytes := testfixture.BuildSecurity(testfixture.SecuritySpec{
		BootKey: boot, LSAKey: lsa, IterationCount: &iteration,
		Secrets: map[string][]byte{
			"$MACHINE.ACC":     []byte("SYNTHETIC_MACHINE_SECRET"),
			"UnknownSynthetic": []byte("SYNTHETIC_OPAQUE_SECRET"),
			"NL$KM":            nlkm,
		},
		CacheEntries: []testfixture.CacheEntry{{Username: "synthetic.one", Domain: "SYNTHETIC.TEST", Verifier: [16]byte{1, 2}}, {Username: "synthetic.two", Domain: "SYNTHETIC.TEST", Verifier: [16]byte{3, 4}}},
	})
	hive, err := registryhive.Open(bytes.NewReader(hiveBytes), int64(len(hiveBytes)), registryhive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Parse(hive, boot)
	if err != nil || result.Status != StatusParsed {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if !result.LSAKeyDerived || result.SecretsFound != 3 || result.SecretsDecoded != 3 || result.CachedDomainFound != 2 || result.CachedDomainDecoded != 2 {
		t.Fatalf("unexpected result: %#v", result)
	}
	for _, secret := range result.Secrets {
		if !secret.Decoded || !secret.RawSecretPresent || secret.SecretLength == 0 {
			t.Fatalf("unexpected secret metadata: %#v", secret)
		}
	}
	for i, cache := range result.CachedDomain {
		if !cache.Decoded || cache.Username == "" || cache.Domain != "SYNTHETIC.TEST" || cache.Iteration != iteration*1024 || len(cache.verifier) != 16 {
			t.Fatalf("unexpected cache metadata %d: %#v", i, cache)
		}
	}
}

func TestCacheVerifierIsNotSerialized(t *testing.T) {
	boot := [16]byte{1}
	nlkm := make([]byte, 32)
	result, err := parseFixture(t, testfixture.SecuritySpec{
		BootKey: boot, LSAKey: [32]byte{2}, Secrets: map[string][]byte{"NL$KM": nlkm},
		CacheEntries: []testfixture.CacheEntry{{Username: "synthetic", Domain: "TEST", Verifier: [16]byte{0xa1, 0xb2}}},
	})
	if err != nil || result.CachedDomainDecoded != 1 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	encoded, err := json.Marshal(result.CachedDomain[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("verifier")) || bytes.Contains(encoded, []byte("a1b2")) {
		t.Fatalf("cache verifier was serialized: %s", encoded)
	}
}

func TestExtractModernCacheKeyUsesSemanticOffset(t *testing.T) {
	body := make([]byte, 32)
	for i := range body {
		body[i] = byte(i + 1)
	}
	key, err := extractModernCacheKey(body)
	if err != nil || len(key) != 16 || key[0] != 1 || key[15] != 16 {
		t.Fatalf("unexpected cache-key extraction: len=%d err=%v", len(key), err)
	}
	for _, short := range [][]byte{nil, make([]byte, 31)} {
		if _, err := extractModernCacheKey(short); err == nil {
			t.Fatal("short NL$KM body accepted")
		}
	}
}

func parseFixture(t *testing.T, spec testfixture.SecuritySpec) (Result, error) {
	t.Helper()
	data := testfixture.BuildSecurity(spec)
	hive, err := registryhive.Open(bytes.NewReader(data), int64(len(data)), registryhive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return Parse(hive, spec.BootKey)
}

func TestParseRejectsWrongBootKeyWithoutSecretMaterial(t *testing.T) {
	boot := [16]byte{1, 2, 3, 4}
	hiveBytes := testfixture.BuildSecurity(testfixture.SecuritySpec{BootKey: boot, LSAKey: [32]byte{5}, Secrets: map[string][]byte{"Synthetic": []byte("VALUE")}})
	hive, err := registryhive.Open(bytes.NewReader(hiveBytes), int64(len(hiveBytes)), registryhive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Parse(hive, [16]byte{9, 9, 9})
	if err == nil || result.Status != StatusMalformed || bytes.Contains([]byte(err.Error()), []byte("VALUE")) {
		t.Fatalf("wrong-key result=%#v err=%v", result, err)
	}
}

func TestParseRejectsTruncatedPolicyBlob(t *testing.T) {
	boot := [16]byte{1, 2, 3, 4}
	hiveBytes := testfixture.BuildSecurity(testfixture.SecuritySpec{BootKey: boot, CorruptPolicy: true})
	hive, err := registryhive.Open(bytes.NewReader(hiveBytes), int64(len(hiveBytes)), registryhive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Parse(hive, boot)
	if err == nil || result.Status != StatusMalformed {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestParseCacheNegativeAndIterationCases(t *testing.T) {
	boot := [16]byte{1}
	lsa := [32]byte{2}
	nlkm := make([]byte, 32)
	base := testfixture.SecuritySpec{
		BootKey: boot, LSAKey: lsa,
		Secrets:      map[string][]byte{"NL$KM": nlkm},
		CacheSlots:   2,
		CacheEntries: []testfixture.CacheEntry{{Username: "synthetic", Domain: "TEST", Verifier: [16]byte{7}}},
	}
	for _, tc := range []struct {
		name string
		spec testfixture.SecuritySpec
		want uint32
	}{
		{name: "default", spec: base, want: 10240},
		{name: "wrong-key", spec: func() testfixture.SecuritySpec { s := base; s.WrongCacheKey = true; return s }(), want: 10240},
		{name: "truncated", spec: func() testfixture.SecuritySpec { s := base; s.CorruptCache = true; return s }(), want: 10240},
		{name: "pathological", spec: func() testfixture.SecuritySpec { s := base; v := uint32(0xffffffff); s.IterationCount = &v; return s }(), want: 10240},
		{name: "malformed-iteration", spec: func() testfixture.SecuritySpec { s := base; s.MalformedIteration = true; return s }(), want: 10240},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := testfixture.BuildSecurity(tc.spec)
			hive, err := registryhive.Open(bytes.NewReader(data), int64(len(data)), registryhive.Options{})
			if err != nil {
				t.Fatal(err)
			}
			result, err := Parse(hive, boot)
			if err != nil || result.CachedDomainFound != 2 || result.CachedDomain[0].Iteration != tc.want {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			if tc.name == "default" && result.CachedDomainDecoded != 1 {
				t.Fatal("valid cache did not decode")
			}
			if (tc.name == "wrong-key" || tc.name == "truncated") && result.CachedDomainDecoded != 0 {
				t.Fatal("invalid cache decoded")
			}
		})
	}
}

func TestParseCacheIncludesEmptySlotsAsMetadataOnly(t *testing.T) {
	boot := [16]byte{1}
	data := testfixture.BuildSecurity(testfixture.SecuritySpec{
		BootKey: boot, LSAKey: [32]byte{2}, Secrets: map[string][]byte{"NL$KM": make([]byte, 32)},
		CacheSlots: 3, CacheEntries: []testfixture.CacheEntry{{Username: "synthetic", Domain: "TEST"}},
	})
	hive, err := registryhive.Open(bytes.NewReader(data), int64(len(data)), registryhive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Parse(hive, boot)
	if err != nil || result.CachedDomainFound != 3 || result.CachedDomainDecoded != 1 || result.CachedDomain[2].MaterialPresent {
		t.Fatalf("empty slot result=%#v err=%v", result, err)
	}
}

func TestParseCacheAcceptsNativeUnalignedEncryptedTail(t *testing.T) {
	boot := [16]byte{1}
	data := testfixture.BuildSecurity(testfixture.SecuritySpec{
		BootKey: boot, LSAKey: [32]byte{2}, Secrets: map[string][]byte{"NL$KM": make([]byte, 32)},
		CacheEntries: []testfixture.CacheEntry{{Username: "synthetic", Domain: "TEST"}}, UnalignedCache: true,
	})
	hive, err := registryhive.Open(bytes.NewReader(data), int64(len(data)), registryhive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Parse(hive, boot)
	if err != nil || result.CachedDomainDecoded != 1 || !result.CachedDomain[0].Decoded {
		t.Fatalf("unaligned cache result=%#v err=%v", result, err)
	}
}
