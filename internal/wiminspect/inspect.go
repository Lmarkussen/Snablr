package wiminspect

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"snablr/internal/artifact"
)

type cliRunner interface {
	LookPath(string) (string, error)
	ListImages(context.Context, string) ([]int, error)
	ListPaths(context.Context, string, int) ([]string, error)
	ExtractFile(context.Context, string, int, string, io.Writer) error
}

type execRunner struct{}

var runner cliRunner = execRunner{}

func ShouldInspect(candidate Candidate, opts Options) (bool, string) {
	if !strings.EqualFold(strings.TrimSpace(candidate.Extension), ".wim") {
		return false, ""
	}
	if !opts.Enabled {
		return false, "wim inspection disabled"
	}
	if opts.AutoWIMMaxSize > 0 && candidate.Size <= opts.AutoWIMMaxSize {
		return true, ""
	}
	if !opts.AllowLargeWIMs {
		if opts.AutoWIMMaxSize > 0 {
			return false, fmt.Sprintf("wim exceeds automatic inspection limit of %d bytes", opts.AutoWIMMaxSize)
		}
		return false, "wim inspection requires an explicit size limit"
	}
	if opts.MaxWIMSize > 0 && candidate.Size > opts.MaxWIMSize {
		return false, fmt.Sprintf("wim exceeds configured inspection limit of %d bytes", opts.MaxWIMSize)
	}
	return true, ""
}

func Inspect(ctx context.Context, content []byte, opts Options, origin artifact.Origin) (Result, error) {
	if opts.MaxBinaryArtifacts <= 0 {
		opts.MaxBinaryArtifacts = 8
	}
	if opts.MaxBinaryBytes <= 0 {
		opts.MaxBinaryBytes = 64 * 1024 * 1024
	}
	if opts.MaxSAMBytes <= 0 {
		opts.MaxSAMBytes = 32 * 1024 * 1024
	}
	if opts.MaxSYSTEMBytes <= 0 {
		opts.MaxSYSTEMBytes = 64 * 1024 * 1024
	}
	if opts.MaxSECURITYBytes <= 0 {
		opts.MaxSECURITYBytes = 64 * 1024 * 1024
	}
	if opts.MaxNTDSBytes <= 0 {
		opts.MaxNTDSBytes = 512 * 1024 * 1024
	}
	if _, err := runner.LookPath("wimlib-imagex"); err != nil {
		return Result{}, fmt.Errorf("wimlib-imagex not available: %w", err)
	}

	workspace, err := os.MkdirTemp("", "snablr-wiminspect-*")
	if err != nil {
		return Result{}, fmt.Errorf("create wim workspace: %w", err)
	}
	var cleanupOnce sync.Once
	var cleanupErr error
	keepWorkspace := false
	cleanup := func() error {
		cleanupOnce.Do(func() { cleanupErr = os.RemoveAll(workspace) })
		return cleanupErr
	}
	defer func() {
		if !keepWorkspace {
			_ = cleanup()
		}
	}()
	tmpFile, err := os.OpenFile(filepath.Join(workspace, "image.wim"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return Result{}, fmt.Errorf("create temp wim: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(content); err != nil {
		_ = tmpFile.Close()
		return Result{}, fmt.Errorf("write temp wim: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return Result{}, fmt.Errorf("close temp wim: %w", err)
	}

	images, err := runner.ListImages(ctx, tmpPath)
	if err != nil {
		return Result{}, err
	}
	if opts.MaxImages <= 0 {
		opts.MaxImages = 4
	}
	if len(images) > opts.MaxImages {
		images = images[:opts.MaxImages]
	}

	result := Result{
		Inspected:        true,
		InspectedLocally: true,
		Members:          make([]Member, 0),
		BinaryMembers:    make([]BinaryMember, 0),
		Cleanup:          cleanup,
	}

	binaryBytes := int64(0)
	textBytes := int64(0)
	for _, imageIndex := range images {
		paths, err := runner.ListPaths(ctx, tmpPath, imageIndex)
		if err != nil {
			return Result{}, err
		}
		seenPaths := make(map[string]struct{}, len(paths))
		for _, rawPath := range paths {
			displayPath := cleanWIMDisplayPath(rawPath)
			memberPath := normalizeWIMPath(rawPath)
			if memberPath == "" || !isTargetedPath(memberPath) {
				continue
			}
			identity := strconv.Itoa(imageIndex) + "\x00" + memberPath
			if _, seen := seenPaths[identity]; seen {
				continue
			}
			seenPaths[identity] = struct{}{}
			if opts.MaxMembers > 0 && len(result.Members)+len(result.BinaryMembers) >= opts.MaxMembers {
				continue
			}

			member := Member{
				Path:      strings.TrimPrefix(displayPath, "/"),
				Name:      path.Base(displayPath),
				Extension: strings.ToLower(filepath.Ext(displayPath)),
			}

			if binaryKind, ok := binaryKindForPath(memberPath); ok {
				if opts.MaxBinaryArtifacts > 0 && len(result.BinaryMembers) >= opts.MaxBinaryArtifacts {
					continue
				}
				limit := binaryLimit(binaryKind, opts)
				if limit <= 0 {
					continue
				}
				binaryOrigin := origin
				binaryOrigin.ContainerType = "wim"
				binaryOrigin.MemberPath = strings.TrimPrefix(displayPath, "/")
				binaryOrigin.ImageIndex = imageIndex
				// Binary artifacts outlive the WIM workspace when a scan-wide
				// coordinator retains an incomplete pair. Keep them in the system
				// temporary directory; artifact ownership controls their cleanup.
				binary, err := artifact.NewTempFile(os.TempDir(), binaryKind, binaryOrigin)
				if err != nil {
					return Result{}, err
				}
				writer, err := binary.OpenWriter(limit)
				if err != nil {
					_ = binary.Close()
					return Result{}, err
				}
				extractErr := runner.ExtractFile(ctx, tmpPath, imageIndex, displayPath, writer)
				closeErr := writer.Close()
				if extractErr != nil || closeErr != nil {
					_ = binary.Close()
					continue
				}
				statSize := binary.Size()
				if opts.MaxBinaryBytes > 0 && binaryBytes+statSize > opts.MaxBinaryBytes {
					_ = binary.Close()
					continue
				}
				binaryBytes += statSize
				result.BinaryMembers = append(result.BinaryMembers, BinaryMember{Path: strings.TrimPrefix(displayPath, "/"), Name: path.Base(displayPath), Extension: strings.ToLower(filepath.Ext(displayPath)), Size: statSize, Artifact: binary})
				continue
			}
			if shouldExtractContent(memberPath) {
				var data []byte
				buf := &boundedBytesBuffer{max: opts.MaxMemberBytes}
				err := runner.ExtractFile(ctx, tmpPath, imageIndex, displayPath, buf)
				if err != nil {
					continue
				}
				data = buf.Bytes()
				if opts.MaxMemberBytes > 0 && int64(len(data)) > opts.MaxMemberBytes {
					continue
				}
				if opts.MaxTotalBytes > 0 && textBytes+int64(len(data)) > opts.MaxTotalBytes {
					continue
				}
				member.Content = data
				member.Size = int64(len(data))
				member.ContentRead = true
				textBytes += int64(len(data))
			}

			result.Members = append(result.Members, member)
		}
	}

	keepWorkspace = true
	return result, nil
}

type boundedBytesBuffer struct {
	data []byte
	max  int64
}

func (b *boundedBytesBuffer) Write(p []byte) (int, error) {
	if b.max >= 0 && int64(len(b.data))+int64(len(p)) > b.max {
		return 0, artifact.ErrTooLarge
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *boundedBytesBuffer) Bytes() []byte { return b.data }

func (execRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (execRunner) ListImages(ctx context.Context, wimPath string) ([]int, error) {
	cmd := exec.CommandContext(ctx, "wimlib-imagex", "info", wimPath)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("list wim contents: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("list wim contents: %w", err)
	}
	re := regexp.MustCompile(`(?i)^Image Count:\s*(\d+)\s*$`)
	for _, line := range strings.Split(string(out), "\n") {
		if m := re.FindStringSubmatch(strings.TrimSpace(line)); len(m) == 2 {
			count, parseErr := strconv.Atoi(m[1])
			if parseErr != nil || count < 1 {
				return nil, fmt.Errorf("invalid WIM image count")
			}
			images := make([]int, count)
			for i := range images {
				images[i] = i + 1
			}
			return images, nil
		}
	}
	return nil, fmt.Errorf("WIM image count not found")
}

func (execRunner) ListPaths(ctx context.Context, wimPath string, imageIndex int) ([]string, error) {
	cmd := exec.CommandContext(ctx, "wimlib-imagex", "dir", wimPath, strconv.Itoa(imageIndex))
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("list wim contents: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("list wim contents: %w", err)
	}
	lines := strings.Split(string(out), "\n")
	paths := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "/" {
			continue
		}
		paths = append(paths, line)
	}
	return paths, nil
}

func (execRunner) ExtractFile(ctx context.Context, wimPath string, imageIndex int, memberPath string, dst io.Writer) error {
	cmd := exec.CommandContext(ctx, "wimlib-imagex", "extract", wimPath, strconv.Itoa(imageIndex), memberPath, "--to-stdout")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("extract WIM member: %w", err)
	}
	_, copyErr := io.Copy(dst, stdout)
	if copyErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if copyErr != nil {
		return copyErr
	}
	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			return fmt.Errorf("extract WIM member: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return fmt.Errorf("extract WIM member: %w", waitErr)
	}
	return nil
}

func normalizeWIMPath(value string) string {
	return strings.ToLower(cleanWIMDisplayPath(value))
}

func cleanWIMDisplayPath(value string) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), `\`, "/")
	if value == "" || value == "." || value == "/" {
		return ""
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(value, "/"))
	if cleaned == "/" || cleaned == "." {
		return ""
	}
	return cleaned
}

func isTargetedPath(memberPath string) bool {
	switch memberPath {
	case "/windows/system32/config/sam",
		"/windows/system32/config/system",
		"/windows/system32/config/security",
		"/windows/ntds/ntds.dit":
		return true
	}
	base := strings.ToLower(path.Base(memberPath))
	if base == "bootstrap.ini" || base == "customsettings.ini" || base == "tasksequence.xml" {
		return true
	}
	return strings.HasPrefix(memberPath, "/windows/panther/") && strings.HasSuffix(memberPath, ".xml")
}

func shouldExtractContent(memberPath string) bool {
	switch strings.ToLower(path.Base(memberPath)) {
	case "bootstrap.ini", "customsettings.ini", "tasksequence.xml":
		return true
	}
	return strings.HasPrefix(memberPath, "/windows/panther/") && strings.HasSuffix(memberPath, ".xml")
}

func binaryKindForPath(memberPath string) (artifact.Kind, bool) {
	return artifact.KindForPath(memberPath)
}

func binaryLimit(kind artifact.Kind, opts Options) int64 {
	switch kind {
	case artifact.KindSAM:
		return opts.MaxSAMBytes
	case artifact.KindSYSTEM:
		return opts.MaxSYSTEMBytes
	case artifact.KindSECURITY:
		return opts.MaxSECURITYBytes
	case artifact.KindNTDS:
		return opts.MaxNTDSBytes
	}
	return 0
}
