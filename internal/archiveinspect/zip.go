package archiveinspect

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"snablr/internal/textdecode"
)

var driveLetterPathPattern = regexp.MustCompile(`(?i)^[a-z]:`)

func ShouldInspect(candidate Candidate, opts Options) (bool, string) {
	resolvedExt := ResolveArchiveExtension(candidate.Name, "", candidate.Extension)
	if !isSupportedArchiveExtension(resolvedExt) {
		return false, ""
	}
	if !opts.Enabled {
		return false, "archive inspection disabled"
	}
	switch resolvedExt {
	case ".zip", ".docx", ".xlsx", ".pptx":
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
	case ".tar", ".tar.gz", ".tgz":
		if opts.AutoTARMaxSize > 0 && candidate.Size <= opts.AutoTARMaxSize {
			return true, ""
		}
		if !opts.AllowLargeTARs {
			if opts.AutoTARMaxSize > 0 {
				return false, fmt.Sprintf("tar archive exceeds automatic inspection limit of %d bytes", opts.AutoTARMaxSize)
			}
			return false, "tar inspection requires an explicit archive size limit"
		}
		if opts.MaxTARSize > 0 && candidate.Size > opts.MaxTARSize {
			return false, fmt.Sprintf("tar archive exceeds configured inspection limit of %d bytes", opts.MaxTARSize)
		}
		return true, ""
	default:
		return false, ""
	}
}

func InspectZIP(content []byte, outerExtension string, opts Options, allowedExtensions map[string]struct{}) (Result, error) {
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

		if !shouldInspectMember(outerExtension, cleanedPath, memberExt, opts, allowedExtensions) {
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
		if isOfficeOpenXMLExtension(outerExtension) && memberExt == ".xml" {
			if extracted := extractOfficeXMLText(data); len(extracted) > 0 {
				data = extracted
			}
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

func isSupportedArchiveExtension(ext string) bool {
	if isOfficeOpenXMLExtension(ext) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(ext)) {
	case ".zip", ".tar", ".tar.gz", ".tgz":
		return true
	default:
		return false
	}
}

func ResolveArchiveExtension(name, filePath, ext string) string {
	lowerName := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(name, `\`, "/")))
	lowerPath := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(filePath, `\`, "/")))
	switch {
	case strings.HasSuffix(lowerName, ".tar.gz"), strings.HasSuffix(lowerPath, ".tar.gz"):
		return ".tar.gz"
	case strings.HasSuffix(lowerName, ".tgz"), strings.HasSuffix(lowerPath, ".tgz"):
		return ".tgz"
	default:
		return strings.ToLower(strings.TrimSpace(ext))
	}
}

func isOfficeOpenXMLExtension(ext string) bool {
	switch strings.ToLower(strings.TrimSpace(ext)) {
	case ".docx", ".xlsx", ".pptx":
		return true
	default:
		return false
	}
}

func shouldInspectMember(outerExtension, memberPath, memberExt string, opts Options, allowedExtensions map[string]struct{}) bool {
	switch strings.ToLower(strings.TrimSpace(outerExtension)) {
	case ".docx":
		if memberExt != ".xml" {
			return false
		}
		return isAllowedOfficeMember(".docx", memberPath)
	case ".xlsx":
		if memberExt != ".xml" {
			return false
		}
		return isAllowedOfficeMember(".xlsx", memberPath)
	case ".pptx":
		if memberExt != ".xml" {
			return false
		}
		return isAllowedOfficeMember(".pptx", memberPath)
	default:
		if _, ok := allowedExtensions[memberExt]; ok && memberExt != "" {
			return true
		}
		return memberExt == "" && opts.InspectExtensionlessText
	}
}

func isAllowedOfficeMember(outerExtension, memberPath string) bool {
	memberPath = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(memberPath, `\`, "/")))
	switch outerExtension {
	case ".docx":
		return memberPath == "word/document.xml" ||
			memberPath == "docprops/core.xml" ||
			memberPath == "docprops/custom.xml" ||
			strings.HasPrefix(memberPath, "word/header") && strings.HasSuffix(memberPath, ".xml") ||
			strings.HasPrefix(memberPath, "word/footer") && strings.HasSuffix(memberPath, ".xml")
	case ".xlsx":
		return memberPath == "xl/sharedstrings.xml" ||
			memberPath == "docprops/core.xml" ||
			memberPath == "docprops/custom.xml" ||
			strings.HasPrefix(memberPath, "xl/worksheets/") && strings.HasSuffix(memberPath, ".xml")
	case ".pptx":
		return memberPath == "docprops/core.xml" ||
			memberPath == "docprops/custom.xml" ||
			strings.HasPrefix(memberPath, "ppt/slides/") && strings.HasSuffix(memberPath, ".xml")
	default:
		return false
	}
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
	switch ResolveArchiveExtension(path.Base(name), name, filepath.Ext(name)) {
	case ".zip", ".tar", ".tar.gz", ".tgz":
		return true
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".7z", ".rar", ".gz", ".bz2", ".xz":
		return true
	default:
		return false
	}
}

func InspectTAR(content []byte, outerExtension string, opts Options, allowedExtensions map[string]struct{}) (Result, error) {
	reader, err := newTARReader(content, outerExtension)
	if err != nil {
		return Result{}, err
	}

	result := Result{
		Inspected:        true,
		InspectedLocally: true,
	}
	totalBytes := int64(0)
	inspectedMembers := 0

	for {
		if opts.MaxMembers > 0 && inspectedMembers >= opts.MaxMembers {
			break
		}

		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Result{}, fmt.Errorf("read tar entry: %w", err)
		}
		if header == nil || header.FileInfo().IsDir() || header.Typeflag != tar.TypeReg {
			continue
		}
		if isSuspiciousArchivePath(header.Name) || isNestedArchive(header.Name) {
			continue
		}

		memberSize := header.Size
		if memberSize < 0 {
			continue
		}
		if opts.MaxMemberBytes > 0 && memberSize > opts.MaxMemberBytes {
			continue
		}
		if opts.MaxTotalUncompressed > 0 && totalBytes+memberSize > opts.MaxTotalUncompressed {
			break
		}

		cleanedPath := cleanedArchivePath(header.Name)
		memberName := path.Base(cleanedPath)
		memberExt := strings.ToLower(filepath.Ext(memberName))
		if !shouldInspectMember(outerExtension, cleanedPath, memberExt, opts, allowedExtensions) {
			continue
		}

		readLimit := memberSize
		if opts.MaxMemberBytes > 0 && readLimit > opts.MaxMemberBytes {
			readLimit = opts.MaxMemberBytes
		}
		data, err := io.ReadAll(io.LimitReader(reader, readLimit+1))
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

func newTARReader(content []byte, outerExtension string) (*tar.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(outerExtension)) {
	case ".tar":
		return tar.NewReader(bytes.NewReader(content)), nil
	case ".tar.gz", ".tgz":
		gzipReader, err := gzip.NewReader(bytes.NewReader(content))
		if err != nil {
			return nil, fmt.Errorf("parse gzip stream: %w", err)
		}
		return tar.NewReader(gzipReader), nil
	default:
		return nil, fmt.Errorf("unsupported tar extension %q", outerExtension)
	}
}

func looksTextLike(data []byte) bool {
	return textdecode.LooksLikeText(data)
}

func extractOfficeXMLText(data []byte) []byte {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	lines := make([]string, 0, 16)
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		charData, ok := token.(xml.CharData)
		if !ok {
			continue
		}
		text := strings.TrimSpace(string(charData))
		if text == "" {
			continue
		}
		lines = append(lines, text)
	}
	if len(lines) == 0 {
		return nil
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}
