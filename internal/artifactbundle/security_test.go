package artifactbundle

import (
	"bytes"
	"context"
	"testing"

	"snablr/internal/artifact"
	"snablr/internal/registryhive"
	"snablr/internal/registryhive/testfixture"
	"snablr/internal/systemkey"
)

func TestCoordinatorParsesSecuritySystemPairAndKeepsSafeSummary(t *testing.T) {
	lsa := [32]byte{5, 6, 7, 8}
	systemBytes := testfixture.Build(testfixture.Spec{Current: uintPtr(1), IncludeSelect: true, IncludeCurrent: true, IncludeControl: true, IncludeLSA: true, Fragments: map[string]string{"JD": "00112233", "Skew1": "22334455", "GBG": "66778899", "Data": "aabbccdd"}})
	systemHive, err := registryhive.Open(bytes.NewReader(systemBytes), int64(len(systemBytes)), registryhive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	derived, err := systemkey.Derive(systemHive)
	if err != nil {
		t.Fatal(err)
	}
	securityBytes := testfixture.BuildSecurity(testfixture.SecuritySpec{BootKey: derived.BootKey, LSAKey: lsa, Secrets: map[string][]byte{"$MACHINE.ACC": []byte("SYNTHETIC")}})
	sys, err := artifact.NewTempFile(t.TempDir(), artifact.KindSYSTEM, artifact.Origin{Host: "host", Share: "share", ContainerPath: "/backup/SYSTEM"})
	if err != nil {
		t.Fatal(err)
	}
	sec, err := artifact.NewTempFile(t.TempDir(), artifact.KindSECURITY, artifact.Origin{Host: "host", Share: "share", ContainerPath: "/backup/SECURITY"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sys.WriteFrom(context.Background(), bytes.NewReader(systemBytes), int64(len(systemBytes))); err != nil {
		t.Fatal(err)
	}
	if _, err := sec.WriteFrom(context.Background(), bytes.NewReader(securityBytes), int64(len(securityBytes))); err != nil {
		t.Fatal(err)
	}
	if sec.Size() != int64(len(securityBytes)) {
		t.Fatalf("security size=%d want=%d", sec.Size(), len(securityBytes))
	}
	c := New(Options{})
	defer c.Close()
	if _, err := c.Add(context.Background(), sec); err != nil {
		t.Fatal(err)
	}
	result, err := c.Add(context.Background(), sys)
	if err != nil || result.SecurityResult == nil || result.SecurityResult.Status != BundleParsed || result.SecurityResult.SecretsDecoded != 1 {
		r := result.SecurityResult
		if r == nil {
			t.Fatalf("security result missing: err=%v", err)
		}
		t.Fatalf("security status=%d decoded=%d revision=%q key=%v failure=%v warnings=%v err=%v", r.Status, r.SecretsDecoded, r.Revision, r.LSAKeyDerived, r.Failure, r.Warnings, err)
	}
	if result.SecurityResult.Secrets[0].RawSecretPresent == false || result.SecurityResult.Secrets[0].SecretLength == 0 {
		t.Fatal("expected only safe secret metadata")
	}
	samBytes := testfixture.BuildSAM(testfixture.SAMSpec{BootKey: derived.BootKey, KeyRevision: 1, IncludeDomain: true, Accounts: []testfixture.SAMAccount{{RID: 500, Username: "synthetic", NTHash: [16]byte{1}, HashRevision: 1}}})
	sam, err := artifact.NewTempFile(t.TempDir(), artifact.KindSAM, artifact.Origin{Host: "host", Share: "share", ContainerPath: "/backup/SAM"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sam.WriteFrom(context.Background(), bytes.NewReader(samBytes), int64(len(samBytes))); err != nil {
		t.Fatal(err)
	}
	samResult, err := c.Add(context.Background(), sam)
	if err != nil || samResult.Result == nil || samResult.Result.Status != BundleParsed {
		t.Fatalf("reverse-order SAM status=%d failure=%v err=%v", samResult.Result.Status, samResult.Result.Failure, err)
	}
}

func uintPtr(v uint32) *uint32 { return &v }
