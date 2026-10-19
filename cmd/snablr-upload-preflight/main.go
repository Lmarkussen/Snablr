// Command snablr-upload-preflight creates a local-only, write-free fixture
// upload plan. Its optional execution mode is explicit create-only upload.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"snablr/internal/fixtureupload"
	"snablr/internal/smb"
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
	dryRun := fs.Bool("dry-run", false, "plan only; do not connect or write")
	execute := fs.Bool("execute-create-only", false, "explicitly authorize the create-only upload")
	verifyRemote := fs.Bool("verify-remote", false, "read and checksum mapped remote files; never writes")
	username := fs.String("username", "", "SMB username (execute mode only)")
	domain := fs.String("domain", "", "SMB domain (execute mode only)")
	passwordEnv := fs.String("password-env", "", "environment variable containing the temporary SMB password")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if !*dryRun && !*execute && !*verifyRemote {
		return errors.New("refusing to run without --dry-run, --verify-remote, or --execute-create-only")
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
	if !*execute {
		if !*verifyRemote {
			return nil
		}
	}
	if *verifyRemote && !*execute {
		if *username == "" || *domain == "" || *passwordEnv == "" {
			return errors.New("verify-remote requires username, domain, and password-env")
		}
		password := os.Getenv(*passwordEnv)
		if password == "" {
			return fmt.Errorf("password environment variable %q is empty", *passwordEnv)
		}
		client := smb.NewClient()
		if err := client.Connect(*server, *domain+`\`+*username, password); err != nil {
			return fmt.Errorf("connect for remote verification: %w", err)
		}
		defer client.Close()
		result, err := fixtureupload.VerifyRemote(context.Background(), client, plan)
		if err != nil {
			return err
		}
		fmt.Printf("remote verification complete: checked=%d mismatches=%d\n", result.Checked, len(result.Mismatches))
		return nil
	}
	if *username == "" || *domain == "" || *passwordEnv == "" {
		return errors.New("execute-create-only requires username, domain, and password-env")
	}
	password := os.Getenv(*passwordEnv)
	if password == "" {
		return fmt.Errorf("password environment variable %q is empty", *passwordEnv)
	}
	client := smb.NewClient()
	if err := client.Connect(*server, *domain+`\`+*username, password); err != nil {
		return fmt.Errorf("connect for create-only preflight: %w", err)
	}
	defer client.Close()
	probe := smbProbe{client: client, server: *server, share: *share}
	if _, err := fixtureupload.Preflight(context.Background(), probe, plan); err != nil {
		return fmt.Errorf("create-only preflight: %w", err)
	}
	result, err := fixtureupload.UploadCreateOnly(context.Background(), client, plan, fixtureupload.CreateAuthorization{ApprovedRoot: *destination, AllowCreate: true})
	if err != nil {
		return fmt.Errorf("create-only upload stopped after %d files: %w", len(result.CreatedFiles), err)
	}
	fmt.Printf("create-only upload complete: directories=%d files=%d\n", len(result.CreatedDirectories), len(result.CreatedFiles))
	return nil
}

type smbProbe struct {
	client *smb.Client
	server string
	share  string
}

func (p smbProbe) Identity(context.Context) (fixtureupload.RemoteIdentity, error) {
	return fixtureupload.RemoteIdentity{Server: p.server, Share: p.share}, nil
}

func (p smbProbe) Exists(_ context.Context, remotePath string) (bool, error) {
	return p.client.Exists(p.share, remotePath)
}
