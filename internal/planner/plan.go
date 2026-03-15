package planner

import (
	"path/filepath"
	"sort"
	"strings"
)

func PlanHosts(inputs []HostInput) []PlannedTarget {
	planned := make([]PlannedTarget, 0, len(inputs))
	for _, input := range inputs {
		score, reasons := scoreHost(input)
		planned = append(planned, PlannedTarget{
			Host:     strings.TrimSpace(input.Host),
			Priority: score,
			Reason:   joinReasons(reasons),
			Source:   strings.TrimSpace(input.Source),
		})
	}
	sortPlanned(planned)
	return planned
}

func PlanShares(inputs []ShareInput, filters FilterOptions) []PlannedTarget {
	planned := make([]PlannedTarget, 0, len(inputs))
	for _, input := range inputs {
		if !shareAllowed(input.Share, filters) {
			continue
		}
		score, reasons := scoreShare(input)
		planned = append(planned, PlannedTarget{
			Host:     strings.TrimSpace(input.Host),
			Share:    strings.TrimSpace(input.Share),
			Priority: score,
			Reason:   joinReasons(reasons),
			Source:   strings.TrimSpace(input.Source),
		})
	}
	sortPlanned(planned)
	return planned
}

func PlanFiles(inputs []FileInput, filters FilterOptions) []PlannedTarget {
	planned := make([]PlannedTarget, 0, len(inputs))
	for _, input := range inputs {
		if !shareAllowed(input.Share, filters) || !pathAllowed(input.Path, filters) {
			continue
		}
		score, reasons := scoreFile(input)
		planned = append(planned, PlannedTarget{
			Host:     strings.TrimSpace(input.Host),
			Share:    strings.TrimSpace(input.Share),
			Path:     strings.TrimSpace(input.Path),
			Priority: score,
			Reason:   joinReasons(reasons),
			Source:   strings.TrimSpace(input.Source),
		})
	}
	sortPlanned(planned)
	return planned
}

func sortPlanned(items []PlannedTarget) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Priority == items[j].Priority {
			if items[i].Host == items[j].Host {
				if items[i].Share == items[j].Share {
					return items[i].Path < items[j].Path
				}
				return items[i].Share < items[j].Share
			}
			return items[i].Host < items[j].Host
		}
		return items[i].Priority > items[j].Priority
	})
}

func joinReasons(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}

	seen := make(map[string]struct{}, len(reasons))
	out := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		reason = strings.TrimSpace(reason)
		if reason == "" {
			continue
		}
		key := strings.ToLower(reason)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, reason)
	}
	return strings.Join(out, "; ")
}

func shareAllowed(name string, filters FilterOptions) bool {
	share := strings.ToLower(strings.TrimSpace(name))
	if share == "" {
		return false
	}
	if len(filters.IncludeShares) > 0 {
		matched := false
		for _, allowed := range filters.IncludeShares {
			if share == strings.ToLower(strings.TrimSpace(allowed)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, blocked := range filters.ExcludeShares {
		if share == strings.ToLower(strings.TrimSpace(blocked)) {
			return false
		}
	}
	return true
}

func pathAllowed(path string, filters FilterOptions) bool {
	normalized := normalizePlanPath(path)
	if normalized == "" {
		return false
	}
	if filters.MaxDepth > 0 && pathDepth(normalized) > filters.MaxDepth {
		return false
	}
	for _, blocked := range filters.ExcludePaths {
		if hasPathPrefix(normalized, blocked) {
			return false
		}
	}
	if len(filters.IncludePaths) == 0 {
		return true
	}
	for _, allowed := range filters.IncludePaths {
		if hasPathPrefix(normalized, allowed) {
			return true
		}
	}
	return false
}

func normalizePlanPath(path string) string {
	path = filepath.ToSlash(strings.TrimSpace(path))
	path = strings.TrimPrefix(path, "./")
	return strings.Trim(path, "/")
}

func hasPathPrefix(path, prefix string) bool {
	path = normalizePlanPath(path)
	prefix = normalizePlanPath(prefix)
	if path == "" || prefix == "" {
		return false
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func pathDepth(path string) int {
	path = normalizePlanPath(path)
	if path == "" {
		return 0
	}
	dir := filepath.ToSlash(filepath.Dir(path))
	dir = strings.Trim(dir, "/")
	if dir == "." || dir == "" {
		return 0
	}
	return len(strings.Split(dir, "/"))
}
