package artifactbundle

import (
	"context"
	"testing"

	"snablr/internal/artifact"
)

// Bundles group by a lowercased key, but their findings name the host and
// share as the scan found them, like every other finding.
func TestBundleOriginKeepsHostAndShareCase(t *testing.T) {
	origin := func(member string) artifact.Origin {
		return artifact.Origin{Host: "FileServer01", Share: "C$", ContainerPath: "backup.wim", MemberPath: member, ContainerType: "wim", ImageIndex: 1}
	}
	sam, system := fixturePair(t, origin(`Windows/System32/config/SAM`), origin(`Windows/System32/config/SYSTEM`))
	c := New(Options{})
	defer c.Close()
	if _, err := c.Add(context.Background(), system); err != nil {
		t.Fatal(err)
	}
	parsed, err := c.Add(context.Background(), sam)
	if err != nil || parsed.Result == nil {
		t.Fatalf("parse: %+v err=%v", parsed, err)
	}
	if got := parsed.Result.Origin; got.Host != "FileServer01" || got.Share != "C$" {
		t.Fatalf("origin host/share=%q/%q, want FileServer01/C$", got.Host, got.Share)
	}
}
