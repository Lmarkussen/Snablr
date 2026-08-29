package artifactbundle

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"snablr/internal/artifact"
	"snablr/internal/registryhive"
	"snablr/internal/registryhive/testfixture"
	"snablr/internal/systemkey"
)

func fixturePair(t *testing.T, originSAM, originSYSTEM artifact.Origin) (*artifact.TempFile, *artifact.TempFile) {
	t.Helper()
	current := uint32(1)
	systemBytes := testfixture.Build(testfixture.Spec{
		Current: &current, IncludeSelect: true, IncludeCurrent: true,
		IncludeControl: true, IncludeLSA: true,
		Fragments: map[string]string{"JD": "00112233", "Skew1": "22334455", "GBG": "66778899", "Data": "aabbccdd"},
	})
	systemHive, err := registryhive.Open(bytes.NewReader(systemBytes), int64(len(systemBytes)), registryhive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	boot, err := systemkey.Derive(systemHive)
	if err != nil {
		t.Fatal(err)
	}
	samBytes := testfixture.BuildSAM(testfixture.SAMSpec{BootKey: boot.BootKey, KeyRevision: 1, IncludeDomain: true,
		Accounts: []testfixture.SAMAccount{{RID: 500, Username: "localadmin", NTHash: [16]byte{1, 2, 3}, HashRevision: 1}}})
	sam, err := artifact.NewTempFile(t.TempDir(), artifact.KindSAM, originSAM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sam.WriteFrom(context.Background(), bytes.NewReader(samBytes), int64(len(samBytes))); err != nil {
		t.Fatal(err)
	}
	system, err := artifact.NewTempFile(t.TempDir(), artifact.KindSYSTEM, originSYSTEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := system.WriteFrom(context.Background(), bytes.NewReader(systemBytes), int64(len(systemBytes))); err != nil {
		t.Fatal(err)
	}
	return sam, system
}

func wimOrigin(member string, image int, container string) artifact.Origin {
	return artifact.Origin{Host: "host", Share: "share", ContainerPath: container, MemberPath: member, ContainerType: "wim", ImageIndex: image}
}

func looseOrigin(file string) artifact.Origin {
	return artifact.Origin{Host: "host", Share: "share", ContainerPath: file}
}

func TestKeyForSeparatesWIMImagesAndContainers(t *testing.T) {
	a := KeyFor(wimOrigin(`Windows\System32\config\SAM`, 1, `backup-a.wim`))
	b := KeyFor(wimOrigin(`Windows/System32/config/SYSTEM`, 1, `backup-a.wim`))
	if a != b {
		t.Fatalf("same WIM image did not normalize equally: %#v %#v", a, b)
	}
	if a == KeyFor(wimOrigin(`Windows/System32/config/SYSTEM`, 2, `backup-a.wim`)) {
		t.Fatal("different WIM images were paired")
	}
	if a == KeyFor(wimOrigin(`Windows/System32/config/SYSTEM`, 1, `backup-b.wim`)) {
		t.Fatal("different WIM containers were paired")
	}
}

func TestKeyForLooseAndRegBackScopes(t *testing.T) {
	if KeyFor(looseOrigin(`/backup/SAM`)) != KeyFor(looseOrigin(`/backup/SYSTEM`)) {
		t.Fatal("same loose directory did not pair")
	}
	if KeyFor(looseOrigin(`/backup-A/SAM`)) == KeyFor(looseOrigin(`/backup-B/SYSTEM`)) {
		t.Fatal("unrelated directories were paired")
	}
	if KeyFor(looseOrigin(`/Windows/System32/config/RegBack/SAM`)) != KeyFor(looseOrigin(`/Windows/System32/config/RegBack/SYSTEM`)) {
		t.Fatal("RegBack files did not pair")
	}
}

func TestKeyForNTDSAndSystemShareWindowsOrigin(t *testing.T) {
	ntds := looseOrigin(`/backup/Windows/NTDS/ntds.dit`)
	system := looseOrigin(`/backup/Windows/System32/config/SYSTEM`)
	if KeyFor(ntds) != KeyFor(system) {
		t.Fatalf("NTDS and SYSTEM from one Windows origin did not pair: %#v %#v", KeyFor(ntds), KeyFor(system))
	}
	if KeyFor(looseOrigin(`/backup-A/Windows/NTDS/ntds.dit`)) == KeyFor(system) {
		t.Fatal("NTDS from another backup origin was paired")
	}
	if KeyFor(wimOrigin(`Windows/NTDS/ntds.dit`, 1, "backup.wim")) != KeyFor(wimOrigin(`Windows/System32/config/SYSTEM`, 1, "backup.wim")) {
		t.Fatal("WIM NTDS and SYSTEM from one image did not pair")
	}
}

func TestCoordinatorParsesOutOfOrderWIMPairAndCleansArtifacts(t *testing.T) {
	sam, system := fixturePair(t, wimOrigin(`Windows/System32/config/SAM`, 1, "backup.wim"), wimOrigin(`Windows/System32/config/SYSTEM`, 1, "backup.wim"))
	c := New(Options{})
	defer c.Close()
	waiting, err := c.Add(context.Background(), system)
	if err != nil || waiting.State != ArtifactWaiting {
		t.Fatalf("SYSTEM add=%#v err=%v", waiting, err)
	}
	parsed, err := c.Add(context.Background(), sam)
	if err != nil || parsed.State != ArtifactParsed || parsed.Result == nil {
		t.Fatalf("SAM add=%#v status=%v accounts=%d errors=%d failure=%v err=%v", parsed, parsed.Result.Status, parsed.Result.AccountCount, len(parsed.Result.AccountErrors), parsed.Result.Failure, err)
	}
	if parsed.Result.Status != BundleParsed || parsed.Result.ControlSet != 1 || parsed.Result.AccountCount != 1 || parsed.Result.RecoveredHashCount != 1 {
		t.Fatalf("unexpected parse result: %#v", parsed.Result)
	}
	if _, err := sam.Open(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("SAM was not closed: %v", err)
	}
	if _, err := system.Open(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("SYSTEM was not closed: %v", err)
	}
}

func TestCoordinatorDoesNotPairDifferentScopes(t *testing.T) {
	sam, system := fixturePair(t, looseOrigin(`/backup-A/SAM`), looseOrigin(`/backup-B/SYSTEM`))
	c := New(Options{})
	defer c.Close()
	if result, err := c.Add(context.Background(), sam); err != nil || result.State != ArtifactWaiting {
		t.Fatalf("SAM add=%#v err=%v", result, err)
	}
	if result, err := c.Add(context.Background(), system); err != nil || result.State != ArtifactWaiting {
		t.Fatalf("SYSTEM add=%#v err=%v", result, err)
	}
	if c.PendingCount() != 2 {
		t.Fatalf("pending bundles=%d", c.PendingCount())
	}
}

func TestCoordinatorDuplicateAndMalformedPair(t *testing.T) {
	sam, system := fixturePair(t, looseOrigin(`/backup/SAM`), looseOrigin(`/backup/SYSTEM`))
	duplicate, err := artifact.NewTempFile(t.TempDir(), artifact.KindSAM, looseOrigin(`/backup/SAM`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := duplicate.WriteFrom(context.Background(), bytes.NewReader([]byte("duplicate")), 64); err != nil {
		t.Fatal(err)
	}
	c := New(Options{})
	defer c.Close()
	if _, err := c.Add(context.Background(), sam); err != nil {
		t.Fatal(err)
	}
	result, err := c.Add(context.Background(), duplicate)
	if err != nil || result.State != ArtifactDuplicate {
		t.Fatalf("duplicate result=%#v err=%v", result, err)
	}
	if _, err := duplicate.Open(); err != nil {
		// Rejected artifacts remain caller-owned.
		t.Fatal(err)
	}
	_ = duplicate.Close()
	bad, err := artifact.NewTempFile(t.TempDir(), artifact.KindSYSTEM, looseOrigin(`/backup/SYSTEM`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.WriteFrom(context.Background(), bytes.NewReader([]byte("not a hive")), 64); err != nil {
		t.Fatal(err)
	}
	parsed, err := c.Add(context.Background(), bad)
	if err != nil || parsed.State != ArtifactMalformed || parsed.Result == nil || parsed.Result.Status != BundleMalformed {
		t.Fatalf("malformed result=%#v err=%v", parsed, err)
	}
	if _, err := bad.Open(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("malformed artifact was not closed: %v", err)
	}
	_ = system.Close()
}

func TestCoordinatorFlushCloseAndLimits(t *testing.T) {
	sam, system := fixturePair(t, looseOrigin(`/one/SAM`), looseOrigin(`/one/SYSTEM`))
	c := New(Options{MaxPendingBundles: 1})
	if _, err := c.Add(context.Background(), sam); err != nil {
		t.Fatal(err)
	}
	other, err := artifact.NewTempFile(t.TempDir(), artifact.KindSAM, looseOrigin(`/two/SAM`))
	if err != nil {
		t.Fatal(err)
	}
	if result, err := c.Add(context.Background(), other); !errors.Is(err, ErrPendingLimit) || result.State != ArtifactRejected {
		t.Fatalf("pending limit result=%#v err=%v", result, err)
	}
	_ = other.Close()
	keys := c.Flush()
	if len(keys) != 1 || c.PendingCount() != 0 {
		t.Fatalf("flush keys=%v pending=%d", keys, c.PendingCount())
	}
	if _, err := sam.Open(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("flushed SAM was not closed: %v", err)
	}
	_ = system.Close()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Add(context.Background(), system); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed coordinator error=%v", err)
	}
}

func TestCoordinatorCancellationCleansCompletePair(t *testing.T) {
	sam, system := fixturePair(t, looseOrigin(`/cancel/SAM`), looseOrigin(`/cancel/SYSTEM`))
	c := New(Options{})
	defer c.Close()
	if _, err := c.Add(context.Background(), sam); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := c.Add(ctx, system)
	if err != nil || result.State != ArtifactFailed || result.Result == nil || result.Result.Status != BundleFailed {
		t.Fatalf("cancel result=%#v err=%v", result, err)
	}
	if _, err := sam.Open(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("canceled SAM was not closed: %v", err)
	}
	if _, err := system.Open(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("canceled SYSTEM was not closed: %v", err)
	}
}

func TestCoordinatorConcurrentDuplicateArrival(t *testing.T) {
	sam1, system := fixturePair(t, looseOrigin(`/parallel/SAM`), looseOrigin(`/parallel/SYSTEM`))
	sam2, system2 := fixturePair(t, looseOrigin(`/parallel/SAM`), looseOrigin(`/parallel/SYSTEM`))
	c := New(Options{MaxConcurrentParsers: 2})
	defer c.Close()
	var wg sync.WaitGroup
	results := make(chan AddResult, 2)
	for _, binary := range []artifact.Binary{sam1, sam2} {
		wg.Add(1)
		go func(binary artifact.Binary) {
			defer wg.Done()
			result, _ := c.Add(context.Background(), binary)
			results <- result
		}(binary)
	}
	wg.Wait()
	close(results)
	duplicateCount := 0
	for result := range results {
		if result.State == ArtifactDuplicate {
			duplicateCount++
		}
	}
	if duplicateCount != 1 {
		t.Fatalf("duplicate results=%d", duplicateCount)
	}
	_ = system.Close()
	_ = system2.Close()
}
