package smb

import (
	"errors"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2"
)

type linkEntry struct{ name string }

func (e linkEntry) Name() string       { return e.name }
func (e linkEntry) Size() int64        { return 0 }
func (e linkEntry) Mode() os.FileMode  { return os.ModeDir | os.ModeSymlink }
func (e linkEntry) ModTime() time.Time { return time.Unix(100, 0) }
func (e linkEntry) IsDir() bool        { return true }
func (e linkEntry) Sys() any           { return nil }

// A share like C$ or SYSVOL: a domain junction the server resolves, a
// symbolic link it refuses (Users\All Users), a profile folder and a folder
// refused for a reason other than access.
func profileTree(refusal error) func(string) ([]os.FileInfo, error) {
	return func(dir string) ([]os.FileInfo, error) {
		switch dir {
		case "":
			return []os.FileInfo{linkEntry{name: "corp.example"}, fakeEntry{name: "Users", dir: true}}, nil
		case `corp.example`:
			return []os.FileInfo{fakeEntry{name: "Groups.xml"}}, nil
		case `Users`:
			return []os.FileInfo{linkEntry{name: "All Users"}, fakeEntry{name: "alice", dir: true}, fakeEntry{name: "refused", dir: true}}, nil
		case `Users\All Users`:
			// The client cannot open the link target (an absolute local path).
			return nil, &os.PathError{Op: "open", Path: `C:\ProgramData`, Err: &smb2.ResponseError{Code: 0xC0000033}}
		case `Users\alice`:
			return []os.FileInfo{fakeEntry{name: "ConsoleHost_history.txt"}}, nil
		case `Users\refused`:
			return nil, refusal
		}
		return nil, nil
	}
}

func walkProfiles(t *testing.T, refusal error, skipped *[]string) ([]string, error) {
	t.Helper()
	var files []string
	opts := WalkOptions{SkippedDirectory: func(path string, err error) {
		*skipped = append(*skipped, path)
	}}
	err := NewClient().walkTree("C$", opts, 10, profileTree(refusal), dirPrefetchInFlight, func(f RemoteFile) error {
		if !f.IsDir {
			files = append(files, f.Path)
		}
		return nil
	})
	return files, err
}

// Junctions are walked, while a link or folder the server refuses is skipped
// and the rest of the share is still walked.
func TestWalkSkipsJunctionsAndRefusedFolders(t *testing.T) {
	refusal := &os.PathError{Op: "open", Path: `Users\refused`, Err: &smb2.InvalidResponseError{Message: "broken error context response format"}}
	var skipped []string
	files, err := walkProfiles(t, refusal, &skipped)
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	if !reflect.DeepEqual(files, []string{"Users/alice/ConsoleHost_history.txt", "corp.example/Groups.xml"}) {
		t.Fatalf("files=%v", files)
	}
	sort.Strings(skipped)
	if !reflect.DeepEqual(skipped, []string{"Users/All Users", "Users/refused"}) {
		t.Fatalf("skipped=%v", skipped)
	}

	status := &os.PathError{Op: "open", Path: `Users\refused`, Err: &smb2.ResponseError{Code: 0xC0000001}}
	skipped = nil
	if _, err := walkProfiles(t, status, &skipped); err != nil || len(skipped) != 2 {
		t.Fatalf("error status: err=%v skipped=%v", err, skipped)
	}
}

// A failure that is not a server answer, such as a timeout or a broken
// connection, still ends the walk, and so does a share root that cannot be
// listed.
func TestWalkStillFailsWhenTheConnectionFails(t *testing.T) {
	var skipped []string
	if _, err := walkProfiles(t, errors.New("SMB operation timed out"), &skipped); err == nil {
		t.Fatal("walk ignored a failed request")
	}
	root := func(string) ([]os.FileInfo, error) {
		return nil, &smb2.ResponseError{Code: 0xC0000001}
	}
	err := NewClient().walkTree("C$", WalkOptions{}, 10, root, dirPrefetchInFlight, func(RemoteFile) error { return nil })
	if err == nil {
		t.Fatal("walk ignored an unreadable share root")
	}
}
