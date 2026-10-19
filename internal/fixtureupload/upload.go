package fixtureupload

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
)

// CreateOnlyWriter is intentionally narrower than the normal SMB writer. Each
// operation must fail if its target already exists; neither operation may
// overwrite or remove data.
type CreateOnlyWriter interface {
	CreateDirectory(share, remotePath string) error
	CreateFileExclusive(share, remotePath string, data []byte) error
}

type CreateAuthorization struct {
	ApprovedRoot string
	AllowCreate  bool
}

type UploadResult struct {
	CreatedDirectories []string `json:"created_directories"`
	CreatedFiles       []string `json:"created_files"`
}

type ContentReader interface {
	ReadFile(share, remotePath string) ([]byte, error)
}

type VerificationResult struct {
	Checked    int      `json:"checked"`
	Mismatches []string `json:"mismatches"`
}

// VerifyRemote reads only the explicitly mapped files and compares their
// bytes to the preflight SHA-256 values. It does not write or repair anything.
func VerifyRemote(ctx context.Context, reader ContentReader, plan Plan) (VerificationResult, error) {
	if reader == nil {
		return VerificationResult{}, errors.New("content reader is required")
	}
	result := VerificationResult{}
	for _, mapping := range plan.Mappings {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
		data, err := reader.ReadFile(plan.Share, mapping.RemotePath)
		if err != nil {
			return result, fmt.Errorf("read remote %s: %w", mapping.RemotePath, err)
		}
		digest := sha256.Sum256(data)
		result.Checked++
		if fmt.Sprintf("%x", digest[:]) != mapping.SourceSHA256 {
			result.Mismatches = append(result.Mismatches, mapping.RemotePath)
		}
	}
	if len(result.Mismatches) > 0 {
		return result, fmt.Errorf("remote checksum mismatches: %d", len(result.Mismatches))
	}
	return result, nil
}

// UploadCreateOnly is the only write-capable operation in this package. It is
// disabled unless the caller explicitly supplies both AllowCreate and the exact
// destination root from the approved plan. It never retries, overwrites, or
// cleans up partial results.
func UploadCreateOnly(ctx context.Context, writer CreateOnlyWriter, plan Plan, auth CreateAuthorization) (UploadResult, error) {
	if writer == nil {
		return UploadResult{}, errors.New("create-only writer is required")
	}
	if !auth.AllowCreate {
		return UploadResult{}, ErrWriteDisabled
	}
	if auth.ApprovedRoot != plan.DestinationRoot {
		return UploadResult{}, fmt.Errorf("approved root mismatch: got %q expected %q", auth.ApprovedRoot, plan.DestinationRoot)
	}
	if err := ValidateDestinationRoot(plan.DestinationRoot); err != nil {
		return UploadResult{}, err
	}
	if len(plan.Mappings) == 0 {
		return UploadResult{}, errors.New("cannot upload an empty plan")
	}

	result := UploadResult{}
	if err := writer.CreateDirectory(plan.Share, plan.DestinationRoot); err != nil {
		return result, fmt.Errorf("create approved root: %w", err)
	}
	result.CreatedDirectories = append(result.CreatedDirectories, plan.DestinationRoot)

	directories := make(map[string]struct{})
	for _, mapping := range plan.Mappings {
		if !mapping.Contained || !strings.HasPrefix(mapping.RemotePath, plan.DestinationRoot+"/") {
			return result, fmt.Errorf("mapping escaped approved root: %s", mapping.RemotePath)
		}
		parent := path.Dir(mapping.RemotePath)
		for parent != "." && parent != plan.DestinationRoot {
			directories[parent] = struct{}{}
			parent = path.Dir(parent)
		}
	}
	directoryList := make([]string, 0, len(directories))
	for directory := range directories {
		directoryList = append(directoryList, directory)
	}
	sort.Slice(directoryList, func(i, j int) bool {
		depthI, depthJ := strings.Count(directoryList[i], "/"), strings.Count(directoryList[j], "/")
		if depthI != depthJ {
			return depthI < depthJ
		}
		return directoryList[i] < directoryList[j]
	})
	for _, directory := range directoryList {
		if err := writer.CreateDirectory(plan.Share, directory); err != nil {
			return result, fmt.Errorf("create mapped directory %s: %w", directory, err)
		}
		result.CreatedDirectories = append(result.CreatedDirectories, directory)
	}

	for _, mapping := range plan.Mappings {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
		data, err := os.ReadFile(mapping.SourcePath)
		if err != nil {
			return result, fmt.Errorf("read source %s: %w", mapping.SourcePath, err)
		}
		digest := sha256.Sum256(data)
		if fmt.Sprintf("%x", digest[:]) != mapping.SourceSHA256 {
			return result, fmt.Errorf("source changed after preflight: %s", mapping.SourcePath)
		}
		if err := writer.CreateFileExclusive(plan.Share, mapping.RemotePath, data); err != nil {
			return result, fmt.Errorf("create mapped file %s: %w", mapping.RemotePath, err)
		}
		result.CreatedFiles = append(result.CreatedFiles, mapping.RemotePath)
	}
	return result, nil
}
