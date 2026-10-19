// Command snablr-upload-preflight creates a local-only, write-free fixture
// upload plan. It has no SMB client and cannot upload or scan.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"snablr/internal/fixtureupload"
)

type manifest struct {
	Fixtures []struct {
		FixtureID string `json:"fixture_id"`
		Path      string `json:"path"`
	} `json:"fixtures"`
}

type output struct {
	Plan fixtureupload.Plan `json:"plan"`
	Mode string             `json:"mode"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("snablr-upload-preflight", flag.ContinueOnError)
	source := fs.String("source-root", "", "local fixture source root")
	manifestPath := fs.String("manifest", "", "locked fixture manifest JSON")
	server := fs.String("server", "", "expected SMB server")
	share := fs.String("share", "", "expected SMB share")
	destination := fs.String("destination-root", "", "proposed dedicated remote root")
	outputPath := fs.String("output", "", "local JSON output path")
	dryRun := fs.Bool("dry-run", false, "required; this command cannot write")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if !*dryRun {
		return errors.New("refusing to run without --dry-run; writes are not implemented")
	}
	if *source == "" || *manifestPath == "" || *server == "" || *share == "" || *destination == "" || *outputPath == "" {
		return errors.New("source-root, manifest, server, share, destination-root, and output are required")
	}
	data, err := os.ReadFile(*manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	var locked manifest
	if err := json.Unmarshal(data, &locked); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}
	expected := make([]string, 0, len(locked.Fixtures))
	ids := make(map[string]string, len(locked.Fixtures))
	for _, fixture := range locked.Fixtures {
		expected = append(expected, fixture.Path)
		ids[filepath.ToSlash(fixture.Path)] = fixture.FixtureID
	}
	plan, err := fixtureupload.BuildPlan(*source, *server, *share, *destination, expected)
	if err != nil {
		return err
	}
	for i := range plan.Mappings {
		plan.Mappings[i].FixtureID = ids[plan.Mappings[i].RelativePath]
	}
	encoded, err := json.MarshalIndent(output{Plan: plan, Mode: "dry-run"}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outputPath, append(encoded, '\n'), 0o600); err != nil {
		return fmt.Errorf("write local plan: %w", err)
	}
	fmt.Printf("dry-run mappings=%d destination=%s output=%s\n", len(plan.Mappings), plan.DestinationRoot, *outputPath)
	return nil
}
