package findings

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"time"
)

type finderProfiler struct {
	dir       string
	started   time.Time
	nextStage int
	seen      map[string]bool
	mu        sync.Mutex
	stages    *os.File
	cpu       *os.File
}

type finderProfileStage struct {
	Stage        string `json:"stage"`
	ElapsedMS    int64  `json:"elapsed_ms"`
	Findings     int    `json:"findings"`
	Credentials  int    `json:"credentials"`
	Correlations int    `json:"correlations"`
	HeapAlloc    uint64 `json:"heap_alloc"`
	HeapInuse    uint64 `json:"heap_inuse"`
	HeapObjects  uint64 `json:"heap_objects"`
	TotalAlloc   uint64 `json:"total_alloc"`
	Mallocs      uint64 `json:"mallocs"`
	Frees        uint64 `json:"frees"`
	NumGC        uint32 `json:"num_gc"`
	PauseTotalNS uint64 `json:"pause_total_ns"`
}

func newFinderProfiler(dir string) (*finderProfiler, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create Finder profile directory: %w", err)
	}
	stages, err := os.OpenFile(filepath.Join(dir, "stages.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("create Finder stage profile: %w", err)
	}
	cpu, err := os.OpenFile(filepath.Join(dir, "cpu.pprof"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		_ = stages.Close()
		return nil, fmt.Errorf("create Finder CPU profile: %w", err)
	}
	if err := pprof.StartCPUProfile(cpu); err != nil {
		_ = stages.Close()
		_ = cpu.Close()
		return nil, fmt.Errorf("start Finder CPU profile: %w", err)
	}
	return &finderProfiler{dir: dir, started: time.Now(), nextStage: PageSize, seen: make(map[string]bool), stages: stages, cpu: cpu}, nil
}

func (p *finderProfiler) close() error {
	if p == nil {
		return nil
	}
	pprof.StopCPUProfile()
	if err := p.stages.Close(); err != nil {
		_ = p.cpu.Close()
		return err
	}
	return p.cpu.Close()
}

func (p *finderProfiler) stage(name string, findings, credentials, correlations int, force bool) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !force && findings < p.nextStage {
		return nil
	}
	if p.seen[name] {
		return nil
	}
	for p.nextStage <= findings {
		p.nextStage += PageSize
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	record := finderProfileStage{
		Stage: name, ElapsedMS: time.Since(p.started).Milliseconds(), Findings: findings,
		Credentials: credentials, Correlations: correlations, HeapAlloc: memory.HeapAlloc,
		HeapInuse: memory.HeapInuse, HeapObjects: memory.HeapObjects, TotalAlloc: memory.TotalAlloc,
		Mallocs: memory.Mallocs, Frees: memory.Frees, NumGC: memory.NumGC, PauseTotalNS: memory.PauseTotalNs,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(p.stages, string(encoded)); err != nil {
		return err
	}
	for _, profile := range []struct {
		name string
		kind string
	}{
		{name: "heap", kind: "heap"},
		{name: "allocs", kind: "allocs"},
	} {
		path := filepath.Join(p.dir, fmt.Sprintf("%s-%s.pprof", sanitizeProfileName(name), profile.name))
		file, err := os.Create(path)
		if err != nil {
			return err
		}
		lookup := pprof.Lookup(profile.kind)
		if lookup == nil {
			_ = file.Close()
			return fmt.Errorf("profile %s is unavailable", profile.kind)
		}
		err = lookup.WriteTo(file, 0)
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	p.seen[name] = true
	return nil
}

func sanitizeProfileName(name string) string {
	name = strings.Trim(name, " .")
	if name == "" {
		return "stage"
	}
	return strings.NewReplacer("/", "_", "\\", "_", " ", "_").Replace(name)
}
