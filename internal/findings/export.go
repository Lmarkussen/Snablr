package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"snablr/internal/output"
)

// ExportOptions describes a deterministic Finder export. Empty ScanID is only
// valid when the database contains exactly one scan.
type ExportOptions struct {
	ScanID   string
	HTMLPath string
	JSONPath string
}

// Export writes the selected Finder projection. Rows are read in bounded pages
// from SQLite; the exporter never depends on the interactive startup page.
func (p *Provider) Export(ctx context.Context, options ExportOptions) error {
	if strings.TrimSpace(options.HTMLPath) == "" && strings.TrimSpace(options.JSONPath) == "" {
		return fmt.Errorf("specify --html and/or --json for a Finder export")
	}
	scan, err := p.exportScan(ctx, options.ScanID)
	if err != nil {
		return err
	}
	if options.HTMLPath != "" {
		if err := p.exportHTML(ctx, scan, options.HTMLPath); err != nil {
			return err
		}
	}
	if options.JSONPath != "" {
		if err := p.exportJSON(ctx, scan, options.JSONPath); err != nil {
			return err
		}
	}
	return nil
}

func (p *Provider) exportScan(ctx context.Context, requested string) (Scan, error) {
	scans, err := p.ListScans(ctx)
	if err != nil {
		return Scan{}, err
	}
	requested = strings.TrimSpace(requested)
	if requested != "" {
		for _, scan := range scans {
			if scan.ID == requested || scan.DisplayID == requested {
				return scan, nil
			}
		}
		return Scan{}, fmt.Errorf("scan %q was not found; choose one of the persisted scan IDs with `snablr find --db %s`", requested, p.Path())
	}
	if len(scans) == 0 {
		return Scan{}, fmt.Errorf("no persisted scans are available for export")
	}
	if len(scans) > 1 {
		return Scan{}, fmt.Errorf("multiple scans are available; pass --scan-id to select one deterministically")
	}
	return scans[0], nil
}

func (p *Provider) exportHTML(ctx context.Context, scan Scan, destination string) error {
	file, commit, err := newExclusiveExportFile(destination)
	if err != nil {
		return fmt.Errorf("create Finder HTML export: %w", err)
	}
	writer, err := output.NewHTMLWriter(file, commit)
	if err != nil {
		_ = file.Close()
		_ = commit.Close()
		return fmt.Errorf("initialize Finder HTML export: %w", err)
	}
	writer.SetScanProfile(scan.Semantics)
	if err := p.streamExportRows(ctx, scan.ID, func(f Finding) error { return writer.WriteFinding(f.Finding) }); err != nil {
		_ = commit.Abort()
		return err
	}
	if err := p.streamCredentials(ctx, scan.ID, func(item Credential) error { return writer.RecordCredentialCandidate(item.Candidate) }); err != nil {
		_ = commit.Abort()
		return err
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finalize Finder HTML export: %w", err)
	}
	return nil
}

func (p *Provider) exportJSON(ctx context.Context, scan Scan, destination string) error {
	file, commit, err := newExclusiveExportFile(destination)
	if err != nil {
		return fmt.Errorf("create Finder JSON export: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			_ = commit.Close()
		} else {
			_ = commit.Abort()
		}
	}()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if _, err := io.WriteString(file, "{\n  \"scan\": "); err != nil {
		return err
	}
	metadata := struct {
		ID           string    `json:"id"`
		DisplayID    string    `json:"display_id"`
		Version      string    `json:"version"`
		Semantics    string    `json:"semantics"`
		Status       string    `json:"status"`
		Targets      string    `json:"targets"`
		Started      time.Time `json:"started_at"`
		Ended        time.Time `json:"ended_at"`
		FindingCount int       `json:"finding_count"`
	}{scan.ID, scan.DisplayID, scan.Version, scan.Semantics, scan.Status, scan.Targets, scan.Started, scan.Ended, scan.FindingCount}
	if err := encoder.Encode(metadata); err != nil {
		return err
	}
	if _, err := io.WriteString(file, ",\n  \"findings\": [\n"); err != nil {
		return err
	}
	first := true
	if err := p.streamExportRows(ctx, scan.ID, func(item Finding) error {
		if !first {
			if _, err := io.WriteString(file, ",\n"); err != nil {
				return err
			}
		}
		first = false
		payload := struct {
			ID          string  `json:"id"`
			PersistedID int64   `json:"persisted_id"`
			Derived     bool    `json:"derived"`
			Fingerprint string  `json:"fingerprint"`
			Finding     Finding `json:"finding"`
		}{item.StableID(), item.ID, item.Derived, item.Fingerprint, item}
		return encodeCompact(file, payload)
	}); err != nil {
		return err
	}
	if _, err := io.WriteString(file, "\n  ],\n  \"credentials\": [\n"); err != nil {
		return err
	}
	first = true
	if err := p.streamCredentials(ctx, scan.ID, func(credential Credential) error {
		if !first {
			if _, err := io.WriteString(file, ",\n"); err != nil {
				return err
			}
		}
		first = false
		return encodeCompact(file, credential)
	}); err != nil {
		return err
	}
	if _, err := io.WriteString(file, "\n  ],\n  \"correlations\": [\n"); err != nil {
		return err
	}
	first = true
	if err := p.streamCorrelations(ctx, scan.ID, func(correlation Correlation) error {
		if !first {
			if _, err := io.WriteString(file, ",\n"); err != nil {
				return err
			}
		}
		first = false
		return encodeCompact(file, correlation)
	}); err != nil {
		return err
	}
	_, err = io.WriteString(file, "\n  ]\n}\n")
	if err == nil {
		if err = commit.Close(); err == nil {
			committed = true
		}
	}
	return err
}

func (p *Provider) streamExportRows(ctx context.Context, scanID string, visit func(Finding) error) error {
	var after int64
	for {
		page, err := p.FindingsAfter(ctx, scanID, after, PageSize)
		if err != nil {
			return fmt.Errorf("read Finder export findings: %w", err)
		}
		for _, item := range page {
			if err := visit(item); err != nil {
				return err
			}
			after = item.ID
		}
		if len(page) < PageSize {
			return nil
		}
	}
}

func (p *Provider) streamCredentials(ctx context.Context, scanID string, visit func(Credential) error) error {
	var offset int
	for {
		page, err := p.Credentials(ctx, scanID, offset, PageSize)
		if err != nil {
			return fmt.Errorf("read Finder export credentials: %w", err)
		}
		for _, item := range page {
			if err := visit(item); err != nil {
				return err
			}
		}
		if len(page) < PageSize {
			return nil
		}
		offset += len(page)
	}
}

func (p *Provider) streamCorrelations(ctx context.Context, scanID string, visit func(Correlation) error) error {
	var offset int
	for {
		page, err := p.Correlations(ctx, scanID, offset, PageSize)
		if err != nil {
			return fmt.Errorf("read Finder export correlations: %w", err)
		}
		for _, item := range page {
			if err := visit(item); err != nil {
				return err
			}
		}
		if len(page) < PageSize {
			return nil
		}
		offset += len(page)
	}
}

func encodeCompact(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

type exclusiveExport struct {
	file        *os.File
	temporary   string
	destination string
	committed   bool
}

func newExclusiveExportFile(destination string) (*os.File, *exclusiveExport, error) {
	destination, err := filepath.Abs(strings.TrimSpace(destination))
	if err != nil || destination == "" {
		return nil, nil, fmt.Errorf("invalid export path %q", destination)
	}
	if _, err := os.Stat(destination); err == nil {
		return nil, nil, fmt.Errorf("export path already exists: %s", destination)
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return nil, nil, err
	}
	file, err := os.CreateTemp(filepath.Dir(destination), ".snablr-export-*")
	if err != nil {
		return nil, nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, nil, err
	}
	commit := &exclusiveExport{file: file, temporary: file.Name(), destination: destination}
	return file, commit, nil
}

func (e *exclusiveExport) Close() error {
	if e == nil || e.file == nil {
		return nil
	}
	if e.committed {
		return nil
	}
	if err := e.file.Sync(); err != nil {
		_ = e.file.Close()
		_ = os.Remove(e.temporary)
		return err
	}
	if err := e.file.Close(); err != nil {
		_ = os.Remove(e.temporary)
		return err
	}
	if e.committed {
		return nil
	}
	if err := os.Link(e.temporary, e.destination); err != nil {
		_ = os.Remove(e.temporary)
		return err
	}
	e.committed = true
	return os.Remove(e.temporary)
}

func (e *exclusiveExport) Abort() error {
	if e == nil || e.file == nil {
		return nil
	}
	closeErr := e.file.Close()
	removeErr := os.Remove(e.temporary)
	return errors.Join(closeErr, removeErr)
}
