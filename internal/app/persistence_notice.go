package app

import (
	"fmt"
	"path/filepath"
	"strings"

	"snablr/internal/config"
	"snablr/pkg/logx"
)

// logPersistenceNotice makes operator-controlled persistent paths visible
// without exposing authentication inputs. Relative paths are displayed as
// absolute paths, while configured storage behavior remains unchanged.
func logPersistenceNotice(cfg config.Config, logger *logx.Logger) {
	if logger == nil {
		return
	}
	var lines []string
	add := func(label, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		absolute, err := filepath.Abs(value)
		if err != nil {
			absolute = filepath.Clean(value)
		}
		lines = append(lines, fmt.Sprintf("  %s: %s", label, absolute))
	}

	add("scanned-target audit", cfg.Output.ScannedTargetsOut)
	if incrementalScanEnabled(cfg) {
		add("incremental state directory", cfg.Scan.StateDir)
		add("incremental inventory", filepath.Join(cfg.Scan.StateDir, "inventory.json"))
	}
	if strings.TrimSpace(cfg.Scan.CheckpointFile) != "" {
		add("checkpoint/resume file", cfg.Scan.CheckpointFile)
	}
	selection, err := config.ParseOutputFormat(cfg.Output.Format)
	if err == nil {
		if selection.JSON {
			add("JSON report", cfg.Output.JSONOut)
		}
		if selection.HTML {
			add("HTML report", cfg.Output.HTMLOut)
		}
	}
	add("CSV export", cfg.Output.CSVOut)
	add("Markdown export", cfg.Output.MDOut)
	add("credential export (highly sensitive)", cfg.Output.CredsOut)

	if len(lines) > 0 {
		logger.Infof("persistent assessment data paths:\n%s\n  Treat state, target inventories, reports, and exports as sensitive engagement data; delete them when no longer needed.", strings.Join(lines, "\n"))
	}
}
