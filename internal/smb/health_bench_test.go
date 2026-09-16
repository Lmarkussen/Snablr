package smb

import (
	"fmt"
	"strconv"
	"testing"
)

// BenchmarkHealthyReadFile measures the healthy-path cost of the bounded
// operation layer (watchdogs, phase bounds and reconnect bookkeeping) when no
// fault occurs.
func BenchmarkHealthyReadFile(b *testing.B) {
	server := newFakeServer()
	const files = 512
	for index := 0; index < files; index++ {
		server.addFile("share", fmt.Sprintf("file-%d.txt", index), []byte("credential=value-"+strconv.Itoa(index)))
	}
	client := NewClient()
	client.dialer = server
	if err := client.ConnectWithAuth("fileserver.example.test", NewPasswordAuth("DOMAIN\\operator", "", "Secret-123!")); err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		name := fmt.Sprintf("file-%d.txt", index%files)
		if _, err := client.ReadFile("share", name); err != nil {
			b.Fatalf("read %s failed: %v", name, err)
		}
	}
}

// BenchmarkHealthyWalkShare measures enumeration cost on the healthy path.
func BenchmarkHealthyWalkShare(b *testing.B) {
	server := newFakeServer()
	const files = 512
	names := make([]string, 0, files)
	for index := 0; index < files; index++ {
		name := fmt.Sprintf("file-%d.txt", index)
		server.addFile("share", name, []byte("credential=value"))
		names = append(names, name)
	}
	server.setDirEntries("share", names...)
	client := NewClient()
	client.dialer = server
	if err := client.ConnectWithAuth("fileserver.example.test", NewPasswordAuth("DOMAIN\\operator", "", "Secret-123!")); err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		seen := 0
		if err := client.WalkShareWithOptions("share", WalkOptions{}, func(RemoteFile) error {
			seen++
			return nil
		}); err != nil {
			b.Fatalf("walk failed: %v", err)
		}
		if seen != files {
			b.Fatalf("walk saw %d entries, want %d", seen, files)
		}
	}
}
