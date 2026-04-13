package app

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"snablr/internal/discovery"
	"snablr/internal/planner"
)

const scannedTargetsTimeFormat = "2006-01-02 15:04:05 MST"

type scannedTargetRecord struct {
	Input      string
	Host       string
	IP         string
	Source     string
	Reachable  bool
	Scanned    bool
	SkipReason string
}

func writeScannedTargets(path string, result discovery.PipelineResult, planned []planner.PlannedTarget) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}

	records := buildScannedTargetRecords(result, planned)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return fmt.Errorf("create scanned-targets directory: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Snablr scanned target audit\n")
	fmt.Fprintf(&b, "# Generated: %s\n", time.Now().UTC().Format(scannedTargetsTimeFormat))
	fmt.Fprintf(&b, "# Targets loaded: %d\n", result.Stats.Loaded)
	fmt.Fprintf(&b, "# Unique targets: %d\n", result.Stats.Unique)
	fmt.Fprintf(&b, "# Reachable SMB hosts: %d\n", result.Stats.Reachable)
	fmt.Fprintf(&b, "# Skipped targets: %d\n", result.Stats.Skipped)
	fmt.Fprintf(&b, "# Columns: source\thost\tip\treachable\tscanned\tskip_reason\tinput\n")
	for _, record := range records {
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			valueOrDash(record.Source),
			valueOrDash(record.Host),
			valueOrDash(record.IP),
			boolWord(record.Reachable),
			boolWord(record.Scanned),
			valueOrDash(record.SkipReason),
			valueOrDash(record.Input),
		)
	}

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write scanned targets audit %s: %w", path, err)
	}
	return nil
}

func buildScannedTargetRecords(result discovery.PipelineResult, planned []planner.PlannedTarget) []scannedTargetRecord {
	scannedHosts := make(map[string]struct{}, len(planned))
	for _, item := range planned {
		host := normalizeTargetAuditValue(item.Host)
		if host == "" {
			continue
		}
		scannedHosts[host] = struct{}{}
	}

	records := make([]scannedTargetRecord, 0, len(result.AllTargets))
	for _, target := range result.AllTargets {
		host := normalizeTargetAuditValue(firstNonEmpty(target.Hostname, target.IP))
		ip := strings.TrimSpace(target.IP)
		_, scanned := scannedHosts[host]
		if !scanned && ip != "" {
			_, scanned = scannedHosts[normalizeTargetAuditValue(ip)]
		}

		record := scannedTargetRecord{
			Input:     strings.TrimSpace(target.Input),
			Host:      strings.TrimSpace(firstNonEmpty(target.Hostname, target.IP)),
			IP:        ip,
			Source:    strings.TrimSpace(target.Source),
			Reachable: target.Reachable445,
			Scanned:   scanned,
		}
		if !record.Reachable {
			record.SkipReason = "unreachable"
		} else if !record.Scanned {
			record.SkipReason = "not planned"
		}
		records = append(records, record)
	}

	sort.Slice(records, func(i, j int) bool {
		left := strings.ToLower(records[i].Host)
		right := strings.ToLower(records[j].Host)
		if left == right {
			if strings.ToLower(records[i].IP) == strings.ToLower(records[j].IP) {
				if strings.ToLower(records[i].Source) == strings.ToLower(records[j].Source) {
					return strings.ToLower(records[i].Input) < strings.ToLower(records[j].Input)
				}
				return strings.ToLower(records[i].Source) < strings.ToLower(records[j].Source)
			}
			return strings.ToLower(records[i].IP) < strings.ToLower(records[j].IP)
		}
		return left < right
	})
	return records
}

func normalizeTargetAuditValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func boolWord(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func valueOrDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}
