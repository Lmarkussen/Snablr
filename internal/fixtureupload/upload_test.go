package fixtureupload

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakeCreateWriter struct {
	dirs, files []string
	failAt      string
}

func (w *fakeCreateWriter) CreateDirectory(_, p string) error {
	if p == w.failAt {
		return errors.New("directory collision")
	}
	w.dirs = append(w.dirs, p)
	return nil
}
func (w *fakeCreateWriter) CreateFileExclusive(_, p string, _ []byte) error {
	if p == w.failAt {
		return errors.New("file collision")
	}
	w.files = append(w.files, p)
	return nil
}

type fakeContentReader struct {
	data map[string][]byte
}

func (r fakeContentReader) ReadFile(_, p string) ([]byte, error) {
	data, ok := r.data[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	return data, nil
}

func TestUploadCreateOnlyRequiresExplicitAuthorization(t *testing.T) {
	plan, err := BuildPlan(testTree(t), "server", "share", "DedicatedRoot", nil)
	if err != nil {
		t.Fatal(err)
	}
	writer := &fakeCreateWriter{}
	if _, err := UploadCreateOnly(context.Background(), writer, plan, CreateAuthorization{}); !errors.Is(err, ErrWriteDisabled) {
		t.Fatalf("got %v", err)
	}
	if len(writer.dirs) != 0 || len(writer.files) != 0 {
		t.Fatal("write attempted without authorization")
	}
}

func TestUploadCreateOnlyCreatesOnlyMappedPathsAndPreservesPartialFailure(t *testing.T) {
	plan, err := BuildPlan(testTree(t), "server", "share", "DedicatedRoot", nil)
	if err != nil {
		t.Fatal(err)
	}
	writer := &fakeCreateWriter{failAt: plan.Mappings[1].RemotePath}
	result, err := UploadCreateOnly(context.Background(), writer, plan, CreateAuthorization{ApprovedRoot: plan.DestinationRoot, AllowCreate: true})
	if err == nil {
		t.Fatal("expected injected failure")
	}
	if len(result.CreatedFiles) != 1 {
		t.Fatalf("expected one committed file before failure, got %v", result.CreatedFiles)
	}
	if len(writer.files) != 1 {
		t.Fatalf("expected no retry/overwrite, got %v", writer.files)
	}
	for _, p := range append(result.CreatedDirectories, result.CreatedFiles...) {
		if p != plan.DestinationRoot && len(p) >= len(plan.DestinationRoot) && p[:len(plan.DestinationRoot)] != plan.DestinationRoot {
			t.Fatalf("escaped root: %s", p)
		}
	}
}

func TestUploadCreateOnlyDetectsSourceChangeBeforeWrite(t *testing.T) {
	root := testTree(t)
	plan, err := BuildPlan(root, "server", "share", "DedicatedRoot", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(plan.Mappings[0].RelativePath)), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	writer := &fakeCreateWriter{}
	_, err = UploadCreateOnly(context.Background(), writer, plan, CreateAuthorization{ApprovedRoot: plan.DestinationRoot, AllowCreate: true})
	if err == nil {
		t.Fatal("expected source-change failure")
	}
	if len(writer.files) != 0 {
		t.Fatal("changed source was written")
	}
}

func TestUploadCreateOnlyRejectsApprovedRootMismatch(t *testing.T) {
	plan, err := BuildPlan(testTree(t), "server", "share", "DedicatedRoot", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = UploadCreateOnly(context.Background(), &fakeCreateWriter{}, plan, CreateAuthorization{ApprovedRoot: "OtherRoot", AllowCreate: true})
	if err == nil {
		t.Fatal("expected root mismatch")
	}
}

func TestVerifyRemoteDetectsChecksumMismatchWithoutWriting(t *testing.T) {
	root := testTree(t)
	plan, err := BuildPlan(root, "server", "share", "DedicatedRoot", nil)
	if err != nil {
		t.Fatal(err)
	}
	data := make(map[string][]byte)
	for _, mapping := range plan.Mappings {
		data[mapping.RemotePath] = []byte("different")
	}
	result, err := VerifyRemote(context.Background(), fakeContentReader{data: data}, plan)
	if err == nil || len(result.Mismatches) != len(plan.Mappings) {
		t.Fatalf("expected all mismatches, result=%+v err=%v", result, err)
	}
}
