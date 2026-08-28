package smbkerberos

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveCCache(t *testing.T) {
	t.Setenv("KRB5CCNAME", "FILE:/tmp/test-cache")
	got, err := ResolveCCache("")
	if err != nil || got != "/tmp/test-cache" {
		t.Fatalf("ResolveCCache = %q, %v", got, err)
	}
	got, err = ResolveCCache("FILE:/var/run/user-cache")
	if err != nil || got != "/var/run/user-cache" {
		t.Fatalf("explicit ResolveCCache = %q, %v", got, err)
	}
}

func TestResolveCCacheRejectsNonFileAndMissing(t *testing.T) {
	t.Setenv("KRB5CCNAME", "")
	if _, err := ResolveCCache(""); err == nil {
		t.Fatal("expected missing cache error")
	}
	if _, err := ResolveCCache("DIR:/tmp/cache"); err == nil {
		t.Fatal("expected unsupported cache error")
	}
}

func TestValidateCCacheMalformedDoesNotPanic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ccache")
	if err := os.WriteFile(path, []byte{5}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCCache(path); err == nil {
		t.Fatal("expected malformed cache error")
	}
}

func TestMechanismOID(t *testing.T) {
	mechanism := &Mechanism{}
	want := []int{1, 2, 840, 113554, 1, 2, 2}
	got := mechanism.OID()
	if len(got) != len(want) {
		t.Fatalf("OID length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("OID arc %d = %d, want %d", i, got[i], want[i])
		}
	}
}

func TestUninitializedMechanismDoesNotExposeSecrets(t *testing.T) {
	mechanism := &Mechanism{}
	if _, _, err := mechanism.InitSecContext(nil); err == nil {
		t.Fatal("expected initialization error")
	}
	if _, err := mechanism.SessionKey(); err == nil {
		t.Fatal("expected session key error")
	}
}
