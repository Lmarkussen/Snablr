package fixtureupload

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "database", "archives"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"database/random-000.conf":       "uid=alice\npwd=pass-a\n",
		"database/archives/random-0.zip": "zip-bytes",
		"database/norsk-0.conf":          "brukernavn=øya\npassord=Pålogg!\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestBuildPlanUsesExplicitRootAndContainsEveryMapping(t *testing.T) {
	root := testTree(t)
	plan, err := BuildPlan(root, "10.1.10.41", "share_iso", "Credentials-R4C4-Recovery-test", []string{
		"database/random-000.conf", "database/archives/random-0.zip", "database/norsk-0.conf",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Mappings) != 3 {
		t.Fatalf("got %d mappings", len(plan.Mappings))
	}
	for _, mapping := range plan.Mappings {
		if !strings.HasPrefix(mapping.RemotePath, plan.DestinationRoot+"/") || !mapping.Contained {
			t.Fatalf("mapping escaped root: %+v", mapping)
		}
		if mapping.RemotePath == "database/"+mapping.RelativePath {
			t.Fatalf("emitted unsafe share-root path: %+v", mapping)
		}
	}
}

func TestBuildPlanRejectsDatabaseMisplacementPattern(t *testing.T) {
	_, err := BuildPlan(testTree(t), "10.1.10.41", "share_iso", "database", nil)
	if !errors.Is(err, ErrInvalidDestinationRoot) {
		t.Fatalf("expected database root rejection, got %v", err)
	}
}

func TestDestinationRootRejectsUnsafeRoots(t *testing.T) {
	for _, root := range []string{"", ".", "..", "/share", `share\\root`, "foo/../bar", "database", "bad\u0301root"} {
		if err := ValidateDestinationRoot(root); err == nil {
			t.Errorf("expected rejection for %q", root)
		}
	}
}

func TestBuildPlanRejectsSymlinksAndMissingFiles(t *testing.T) {
	root := testTree(t)
	if err := os.Symlink(filepath.Join(root, "database", "random-000.conf"), filepath.Join(root, "database", "link.conf")); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPlan(root, "server", "share", "DedicatedRoot", nil); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
	if _, err := BuildPlan(testTree(t), "server", "share", "DedicatedRoot", []string{"database/missing.conf"}); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected manifest mismatch, got %v", err)
	}
}

func TestBuildPlanRejectsDuplicateExpectedPathsAndTraversal(t *testing.T) {
	root := testTree(t)
	if _, err := BuildPlan(root, "server", "share", "DedicatedRoot", []string{"database/random-000.conf", "database/random-000.conf"}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate rejection, got %v", err)
	}
	if _, err := BuildPlan(root, "server", "share", "DedicatedRoot", []string{"../escape"}); err == nil {
		t.Fatal("expected traversal rejection")
	}
}

func TestBuildPlanRejectsCaseInsensitiveDestinationCollisions(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{"A.conf": "a", "a.conf": "b"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := BuildPlan(root, "server", "share", "DedicatedRoot", nil)
	if !errors.Is(err, ErrDestinationCollision) {
		t.Fatalf("expected case-insensitive collision rejection, got %v", err)
	}
}

type fakeProbe struct {
	identity RemoteIdentity
	existing map[string]bool
	err      error
}

func (p fakeProbe) Identity(context.Context) (RemoteIdentity, error) { return p.identity, p.err }
func (p fakeProbe) Exists(_ context.Context, path string) (bool, error) {
	return p.existing[path], p.err
}

func TestPreflightRejectsWrongServerShareRootChildAndPassesCleanPlan(t *testing.T) {
	root := testTree(t)
	plan, err := BuildPlan(root, "10.1.10.41", "share_iso", "DedicatedRoot", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Preflight(context.Background(), fakeProbe{identity: RemoteIdentity{Server: "other", Share: "share_iso"}}, plan); err == nil {
		t.Fatal("expected identity mismatch")
	}
	if _, err := Preflight(context.Background(), fakeProbe{identity: RemoteIdentity{Server: plan.Server, Share: plan.Share}, existing: map[string]bool{plan.DestinationRoot: true}}, plan); !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("expected root collision, got %v", err)
	}
	child := plan.Mappings[0].RemotePath
	if _, err := Preflight(context.Background(), fakeProbe{identity: RemoteIdentity{Server: plan.Server, Share: plan.Share}, existing: map[string]bool{child: true}}, plan); err == nil || !strings.Contains(err.Error(), "collisions=1") {
		t.Fatalf("expected child collision, got %v", err)
	}
	result, err := Preflight(context.Background(), fakeProbe{identity: RemoteIdentity{Server: plan.Server, Share: plan.Share}}, plan)
	if err != nil || !result.Passed {
		t.Fatalf("expected clean preflight, result=%+v err=%v", result, err)
	}
}

func TestPreflightPropagatesReadOnlyProbeFailure(t *testing.T) {
	root := testTree(t)
	plan, err := BuildPlan(root, "server", "share", "DedicatedRoot", nil)
	if err != nil {
		t.Fatal(err)
	}
	probeErr := errors.New("authentication failed")
	_, err = Preflight(context.Background(), fakeProbe{err: probeErr}, plan)
	if !errors.Is(err, probeErr) {
		t.Fatalf("expected probe error to be preserved, got %v", err)
	}
}

func TestExecuteAlwaysFailsClosedAndNeverWrites(t *testing.T) {
	if err := Execute(context.Background(), Plan{}, false); !errors.Is(err, ErrWriteDisabled) {
		t.Fatalf("expected dry-run write refusal, got %v", err)
	}
	if err := Execute(context.Background(), Plan{}, true); !errors.Is(err, ErrWriteDisabled) {
		t.Fatalf("expected write refusal, got %v", err)
	}
}
