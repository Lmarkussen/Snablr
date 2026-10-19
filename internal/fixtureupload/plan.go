// Package fixtureupload contains fail-closed planning and preflight helpers for
// controlled synthetic fixture uploads. It intentionally has no SMB writer.
package fixtureupload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

var (
	ErrInvalidDestinationRoot = errors.New("invalid fixture destination root")
	ErrDestinationExists      = errors.New("fixture destination already exists")
	ErrDestinationCollision   = errors.New("fixture destination collision")
	ErrWriteDisabled          = errors.New("fixture writes are disabled by this helper")
)

type Mapping struct {
	FixtureID       string `json:"fixture_id,omitempty"`
	SourcePath      string `json:"source_path"`
	RelativePath    string `json:"relative_path"`
	RemotePath      string `json:"remote_path"`
	Size            int64  `json:"size"`
	SourceSHA256    string `json:"source_sha256"`
	Contained       bool   `json:"contained"`
	CollisionStatus string `json:"collision_status"`
}

type Plan struct {
	SourceRoot      string    `json:"source_root"`
	Server          string    `json:"server"`
	Share           string    `json:"share"`
	DestinationRoot string    `json:"destination_root"`
	Mappings        []Mapping `json:"mappings"`
}

type RemoteIdentity struct {
	Server string
	Share  string
}

type RemoteProbe interface {
	Identity(context.Context) (RemoteIdentity, error)
	Exists(context.Context, string) (bool, error)
}

type RemotePreflight struct {
	Identity           RemoteIdentity `json:"identity"`
	ExpectedIdentity   RemoteIdentity `json:"expected_identity"`
	RootExists         bool           `json:"root_exists"`
	ExistingChildren   []string       `json:"existing_children"`
	MappingCount       int            `json:"mapping_count"`
	CollisionCount     int            `json:"collision_count"`
	ContainmentFailure int            `json:"containment_failures"`
	Passed             bool           `json:"passed"`
}

// ValidateDestinationRoot accepts one dedicated SMB directory name only. This
// prevents a caller from accidentally treating a share root or a nested path
// such as database/ as the upload root.
func ValidateDestinationRoot(root string) error {
	if strings.TrimSpace(root) == "" || root == "." || root == ".." {
		return fmt.Errorf("%w: root is empty or relative traversal", ErrInvalidDestinationRoot)
	}
	if strings.ContainsAny(root, `/\\`) || filepath.IsAbs(root) {
		return fmt.Errorf("%w: root must be one relative directory name", ErrInvalidDestinationRoot)
	}
	if strings.EqualFold(root, "database") {
		return fmt.Errorf("%w: top-level database is reserved", ErrInvalidDestinationRoot)
	}
	for _, r := range root {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Mn, r) {
			return fmt.Errorf("%w: root contains unsafe character", ErrInvalidDestinationRoot)
		}
	}
	return nil
}

func normalizeRelativePath(raw string) (string, error) {
	if raw == "" || filepath.IsAbs(raw) || strings.HasPrefix(raw, "/") || strings.Contains(raw, "\\") {
		return "", fmt.Errorf("invalid relative source path %q", raw)
	}
	clean := path.Clean(strings.ReplaceAll(raw, string(filepath.Separator), "/"))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("path escapes source root: %q", raw)
	}
	for _, r := range clean {
		if unicode.Is(unicode.Mn, r) {
			return "", fmt.Errorf("path uses unverified Unicode normalization: %q", raw)
		}
	}
	return clean, nil
}

func canonicalCollisionKey(remotePath string) string {
	return strings.ToLower(remotePath)
}

// BuildPlan enumerates regular files and creates an explicit source-to-remote
// mapping. expectedRelativePaths, when non-empty, must exactly match the source
// file set; this prevents a partial staging tree from being uploaded.
func BuildPlan(sourceRoot, server, share, destinationRoot string, expectedRelativePaths []string) (Plan, error) {
	if strings.TrimSpace(sourceRoot) == "" {
		return Plan{}, errors.New("source root is empty")
	}
	if strings.TrimSpace(server) == "" || strings.TrimSpace(share) == "" {
		return Plan{}, errors.New("server and share are required")
	}
	if err := ValidateDestinationRoot(destinationRoot); err != nil {
		return Plan{}, err
	}
	resolved, err := filepath.EvalSymlinks(sourceRoot)
	if err != nil {
		return Plan{}, fmt.Errorf("resolve source root: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return Plan{}, fmt.Errorf("stat source root: %w", err)
	}
	if !info.IsDir() {
		return Plan{}, fmt.Errorf("source root is not a directory: %s", sourceRoot)
	}

	rootSlash := destinationRoot + "/"
	plan := Plan{SourceRoot: resolved, Server: server, Share: share, DestinationRoot: destinationRoot}
	seen := make(map[string]string)
	actual := make(map[string]struct{})
	err = filepath.WalkDir(resolved, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filePath == resolved {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink or redirection is not permitted: %s", filePath)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("non-regular source is not permitted: %s", filePath)
		}
		relRaw, err := filepath.Rel(resolved, filePath)
		if err != nil {
			return err
		}
		rel, err := normalizeRelativePath(relRaw)
		if err != nil {
			return err
		}
		actual[rel] = struct{}{}
		remote := rootSlash + rel
		key := canonicalCollisionKey(remote)
		if previous, exists := seen[key]; exists {
			return fmt.Errorf("%w: %s and %s", ErrDestinationCollision, previous, remote)
		}
		seen[key] = remote
		stat, err := entry.Info()
		if err != nil {
			return err
		}
		hash, err := fileSHA256(filePath)
		if err != nil {
			return fmt.Errorf("hash %s: %w", filePath, err)
		}
		plan.Mappings = append(plan.Mappings, Mapping{
			SourcePath: filePath, RelativePath: rel, RemotePath: remote,
			Size: stat.Size(), SourceSHA256: hash, Contained: strings.HasPrefix(remote, rootSlash),
			CollisionStatus: "clear",
		})
		return nil
	})
	if err != nil {
		return Plan{}, err
	}
	sort.Slice(plan.Mappings, func(i, j int) bool { return plan.Mappings[i].RelativePath < plan.Mappings[j].RelativePath })
	if len(expectedRelativePaths) > 0 {
		expected := make(map[string]struct{}, len(expectedRelativePaths))
		for _, raw := range expectedRelativePaths {
			rel, err := normalizeRelativePath(raw)
			if err != nil {
				return Plan{}, fmt.Errorf("expected path: %w", err)
			}
			if _, exists := expected[rel]; exists {
				return Plan{}, fmt.Errorf("duplicate expected source path: %s", rel)
			}
			expected[rel] = struct{}{}
		}
		if len(expected) != len(actual) {
			return Plan{}, fmt.Errorf("source/manifest file-count mismatch: source=%d expected=%d", len(actual), len(expected))
		}
		for rel := range expected {
			if _, exists := actual[rel]; !exists {
				return Plan{}, fmt.Errorf("manifest source path missing from staging tree: %s", rel)
			}
		}
	}
	return plan, nil
}

func fileSHA256(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

// Preflight performs only identity, root, and child collision checks. It never
// opens a write-capable SMB operation.
func Preflight(ctx context.Context, probe RemoteProbe, plan Plan) (RemotePreflight, error) {
	if probe == nil {
		return RemotePreflight{}, errors.New("remote probe is required")
	}
	identity, err := probe.Identity(ctx)
	if err != nil {
		return RemotePreflight{}, fmt.Errorf("read remote identity: %w", err)
	}
	result := RemotePreflight{Identity: identity, ExpectedIdentity: RemoteIdentity{Server: plan.Server, Share: plan.Share}, MappingCount: len(plan.Mappings)}
	if !strings.EqualFold(identity.Server, plan.Server) || !strings.EqualFold(identity.Share, plan.Share) {
		return result, fmt.Errorf("remote identity mismatch: got %s/%s expected %s/%s", identity.Server, identity.Share, plan.Server, plan.Share)
	}
	rootExists, err := probe.Exists(ctx, plan.DestinationRoot)
	if err != nil {
		return result, fmt.Errorf("check destination root: %w", err)
	}
	result.RootExists = rootExists
	if rootExists {
		return result, fmt.Errorf("%w: %s", ErrDestinationExists, plan.DestinationRoot)
	}
	for _, mapping := range plan.Mappings {
		if !mapping.Contained {
			result.ContainmentFailure++
			continue
		}
		exists, err := probe.Exists(ctx, mapping.RemotePath)
		if err != nil {
			return result, fmt.Errorf("check destination %s: %w", mapping.RemotePath, err)
		}
		if exists {
			result.ExistingChildren = append(result.ExistingChildren, mapping.RemotePath)
		}
	}
	result.CollisionCount = len(result.ExistingChildren)
	result.Passed = result.MappingCount > 0 && result.CollisionCount == 0 && result.ContainmentFailure == 0
	if !result.Passed {
		return result, fmt.Errorf("remote preflight failed: collisions=%d containment=%d", result.CollisionCount, result.ContainmentFailure)
	}
	return result, nil
}

// Execute is deliberately fail-closed. A future write adapter must be added
// separately after explicit operator authorization and exclusive-create support
// are demonstrated; this package cannot write to SMB.
func Execute(context.Context, Plan, bool) error {
	return ErrWriteDisabled
}
