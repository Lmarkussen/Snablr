package seed

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func NewManifest(prefix string) Manifest {
	return Manifest{
		GeneratedAt: time.Now().UTC(),
		SeedPrefix:  normalizeSeedPrefix(prefix),
		Entries:     make([]SeedManifestEntry, 0),
	}
}

func (m *Manifest) Recalculate() {
	if m == nil {
		return
	}
	m.FileCount = len(m.Entries)
	m.DirectoryCount = 0
	m.Families = make(map[string]int)
	directories := make(map[string]struct{})
	for _, entry := range m.Entries {
		path := filepath.ToSlash(entry.Path)
		if index := strings.LastIndex(path, "/"); index >= 0 {
			for parent := path[:index]; parent != ""; {
				directories[parent] = struct{}{}
				cut := strings.LastIndex(parent, "/")
				if cut < 0 {
					break
				}
				parent = parent[:cut]
			}
		}
		family := entry.Category
		if family != "" {
			m.Families[family]++
		}
	}
	m.DirectoryCount = len(directories)
}

func (m *Manifest) Add(entry SeedManifestEntry) {
	if m == nil {
		return
	}
	m.Entries = append(m.Entries, entry)
}

func (m Manifest) Write(path string) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create manifest directory: %w", err)
		}
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write manifest %s: %w", path, err)
	}
	return nil
}

func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest %s: %w", path, err)
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest %s: %w", path, err)
	}
	if manifest.Entries == nil {
		manifest.Entries = make([]SeedManifestEntry, 0)
	}
	return manifest, nil
}
