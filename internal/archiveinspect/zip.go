package archiveinspect

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

var driveLetterPathPattern = regexp.MustCompile(`(?i)^[a-z]:`)

func ShouldInspect(candidate Candidate, opts Options) (bool, string) {
	if !strings.EqualFold(strings.TrimSpace(candidate.Extension), ".zip") {
		return false, ""
	}
	if !opts.Enabled {
		return false, "archive inspection disabled"
	}
	if opts.AutoZIPMaxSize > 0 && candidate.Size <= opts.AutoZIPMaxSize {
		return true, ""
	}
	if !opts.AllowLargeZIPs {
		if opts.AutoZIPMaxSize > 0 {
			return false, fmt.Sprintf("zip exceeds automatic inspection limit of %d bytes", opts.AutoZIPMaxSize)
		}
		return false, "zip inspection requires an explicit archive size limit"
	}
	if opts.MaxZIPSize > 0 && candidate.Size > opts.MaxZIPSize {
		return false, fmt.Sprintf("zip exceeds configured inspection limit of %d bytes", opts.MaxZIPSize)
	}
	return true, ""
}

func InspectZIP(content []byte, opts Options, allowedExtensions map[string]struct{}) (Result, error) {
	reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return Result{}, fmt.Errorf("parse zip: %w", err)
	}

	result := Result{
		Inspected:        true,
		InspectedLocally: true,
	}
	totalBytes := int64(0)
	inspectedMembers := 0

	for _, file := range reader.File {
		if opts.MaxMembers > 0 && inspectedMembers >= opts.MaxMembers {
			break
		}
		if file.FileInfo().IsDir() {
			continue
		}
		if isEncrypted(file) || isSuspiciousArchivePath(file.Name) || isNestedArchive(file.Name) {
			continue
		}
		memberSize := int64(file.UncompressedSize64)
		if opts.MaxMemberBytes > 0 && memberSize > opts.MaxMemberBytes {
			continue
		}
		if opts.MaxTotalUncompressed > 0 && totalBytes+memberSize > opts.MaxTotalUncompressed {
			break
		}

		cleanedPath := cleanedArchivePath(file.Name)
		memberName := path.Base(cleanedPath)
		memberExt := strings.ToLower(filepath.Ext(memberName))

		shouldRead := false
		extensionless := memberExt == ""
		if _, ok := allowedExtensions[memberExt]; ok && memberExt != "" {
			shouldRead = true
		} else if extensionless && opts.InspectExtensionlessText {
			shouldRead = true
		}
		if !shouldRead {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			continue
		}
		readLimit := memberSize
		if opts.MaxMemberBytes > 0 && readLimit > opts.MaxMemberBytes {
			readLimit = opts.MaxMemberBytes
		}
		if readLimit <= 0 {
			readLimit = memberSize
		}
		data, err := io.ReadAll(io.LimitReader(rc, readLimit+1))
		_ = rc.Close()
		if err != nil {
			continue
		}
		if opts.MaxMemberBytes > 0 && int64(len(data)) > opts.MaxMemberBytes {
			continue
		}
		if !looksTextLike(data) {
			continue
		}

		totalBytes += int64(len(data))
		inspectedMembers++
		result.Members = append(result.Members, Member{
			Path:      cleanedPath,
			Name:      memberName,
			Extension: memberExt,
			Size:      int64(len(data)),
			Content:   data,
		})
	}

	return result, nil
}

func cleanedArchivePath(name string) string {
	cleaned := strings.ReplaceAll(strings.TrimSpace(name), `\`, "/")
	cleaned = path.Clean(cleaned)
	cleaned = strings.TrimPrefix(cleaned, "./")
	return cleaned
}

func isEncrypted(file *zip.File) bool {
	return file.Flags&0x1 != 0
}

func isSuspiciousArchivePath(name string) bool {
	cleaned := cleanedArchivePath(name)
	if cleaned == "." || cleaned == ".." {
		return true
	}
	if strings.HasPrefix(cleaned, "/") || strings.HasPrefix(cleaned, "../") {
		return true
	}
	if driveLetterPathPattern.MatchString(cleaned) {
		return true
	}
	return false
}

func isNestedArchive(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz":
		return true
	default:
		return false
	}
}

func looksTextLike(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if bytes.IndexByte(data, 0x00) >= 0 {
		return false
	}
	sample := data
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	if !utf8.Valid(sample) {
		return false
	}
	printable := 0
	for _, b := range sample {
		if b == '\n' || b == '\r' || b == '\t' {
			printable++
			continue
		}
		if b >= 32 && b <= 126 {
			printable++
		}
	}
	return float64(printable)/float64(len(sample)) >= 0.85
}
