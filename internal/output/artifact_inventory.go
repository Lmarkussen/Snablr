package output

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"snablr/internal/scanner"
)

var backupArtifactExtensions = map[string]struct{}{
	".bak": {},
	".wim": {},
	".mtf": {},
}

type backupArtifactTypeSummary struct {
	Extension string `json:"extension"`
	Count     int    `json:"count"`
}

type backupArtifactRecord struct {
	Host      string `json:"host,omitempty"`
	Share     string `json:"share,omitempty"`
	ShareType string `json:"share_type,omitempty"`
	Source    string `json:"source,omitempty"`
	FilePath  string `json:"file_path"`
	UNCPath   string `json:"unc_path,omitempty"`
	Extension string `json:"extension"`
	Size      int64  `json:"size,omitempty"`
}

type backupArtifactInventory struct {
	Enabled bool                        `json:"enabled"`
	Total   int                         `json:"total"`
	ByType  []backupArtifactTypeSummary `json:"by_type,omitempty"`
	Items   []backupArtifactRecord      `json:"items,omitempty"`
}

type backupArtifactCollector struct {
	mu      sync.Mutex
	enabled bool
	items   map[string]backupArtifactRecord
}

func newBackupArtifactCollector() *backupArtifactCollector {
	return &backupArtifactCollector{
		items: make(map[string]backupArtifactRecord),
	}
}

func (c *backupArtifactCollector) SetEnabled(enabled bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
}

func (c *backupArtifactCollector) RecordFile(meta scanner.FileMetadata) {
	if c == nil {
		return
	}
	meta = meta.Normalized()

	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return
	}

	ext := strings.ToLower(strings.TrimSpace(meta.Extension))
	if _, ok := backupArtifactExtensions[ext]; !ok {
		return
	}

	record := backupArtifactRecord{
		Host:      strings.TrimSpace(meta.Host),
		Share:     strings.TrimSpace(meta.Share),
		ShareType: strings.TrimSpace(meta.ShareType),
		Source:    strings.TrimSpace(meta.Source),
		FilePath:  meta.FilePath,
		Extension: ext,
		Size:      meta.Size,
		UNCPath:   backupArtifactUNCPath(meta),
	}
	c.items[backupArtifactKey(meta)] = record
}

func (c *backupArtifactCollector) Snapshot() *backupArtifactInventory {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return nil
	}

	items := make([]backupArtifactRecord, 0, len(c.items))
	typeCounts := make(map[string]int, len(backupArtifactExtensions))
	for _, item := range c.items {
		items = append(items, item)
		typeCounts[item.Extension]++
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Host != items[j].Host {
			return strings.ToLower(items[i].Host) < strings.ToLower(items[j].Host)
		}
		if items[i].Share != items[j].Share {
			return strings.ToLower(items[i].Share) < strings.ToLower(items[j].Share)
		}
		return strings.ToLower(items[i].FilePath) < strings.ToLower(items[j].FilePath)
	})

	byType := make([]backupArtifactTypeSummary, 0, len(typeCounts))
	for ext, count := range typeCounts {
		byType = append(byType, backupArtifactTypeSummary{Extension: ext, Count: count})
	}
	sort.Slice(byType, func(i, j int) bool {
		if byType[i].Count == byType[j].Count {
			return byType[i].Extension < byType[j].Extension
		}
		return byType[i].Count > byType[j].Count
	})

	return &backupArtifactInventory{
		Enabled: true,
		Total:   len(items),
		ByType:  byType,
		Items:   items,
	}
}

func backupArtifactKey(meta scanner.FileMetadata) string {
	return strings.ToLower(fmt.Sprintf("%s|%s|%s", strings.TrimSpace(meta.Host), strings.TrimSpace(meta.Share), strings.TrimSpace(meta.FilePath)))
}

func backupArtifactUNCPath(meta scanner.FileMetadata) string {
	path := strings.TrimSpace(strings.ReplaceAll(meta.FilePath, "/", `\`))
	host := strings.TrimSpace(meta.Host)
	share := strings.TrimSpace(meta.Share)
	if host == "" || share == "" {
		return path
	}
	if path != "" && !strings.HasPrefix(path, `\`) {
		path = `\` + path
	}
	return fmt.Sprintf(`\\%s\%s%s`, host, share, path)
}
