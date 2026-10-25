package app

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

type scannerProfiler struct {
	started time.Time
	stages  *os.File
	cpu     *os.File
	stop    chan struct{}
	done    chan struct{}
	close   sync.Once
}

type scannerProfileSample struct {
	ElapsedMS   int64  `json:"elapsed_ms"`
	HeapAlloc   uint64 `json:"heap_alloc"`
	HeapInuse   uint64 `json:"heap_inuse"`
	HeapObjects uint64 `json:"heap_objects"`
	TotalAlloc  uint64 `json:"total_alloc"`
	Mallocs     uint64 `json:"mallocs"`
	Frees       uint64 `json:"frees"`
	NumGC       uint32 `json:"num_gc"`
	Goroutines  int    `json:"goroutines"`
}

func newScannerProfilerFromEnv() (*scannerProfiler, error) {
	dir := strings.TrimSpace(os.Getenv("SNABLR_SCANNER_PROFILE_DIR"))
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create scanner profile directory: %w", err)
	}
	stages, err := os.OpenFile(filepath.Join(dir, "runtime.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("create scanner runtime profile: %w", err)
	}
	cpu, err := os.OpenFile(filepath.Join(dir, "cpu.pprof"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		_ = stages.Close()
		return nil, fmt.Errorf("create scanner CPU profile: %w", err)
	}
	if err := pprof.StartCPUProfile(cpu); err != nil {
		_ = stages.Close()
		_ = cpu.Close()
		return nil, fmt.Errorf("start scanner CPU profile: %w", err)
	}
	profiler := &scannerProfiler{started: time.Now(), stages: stages, cpu: cpu, stop: make(chan struct{}), done: make(chan struct{})}
	go profiler.sampleLoop()
	return profiler, nil
}

func (p *scannerProfiler) sampleLoop() {
	defer close(p.done)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.writeSample()
		case <-p.stop:
			p.writeSample()
			return
		}
	}
}

func (p *scannerProfiler) writeSample() {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	encoded, err := json.Marshal(scannerProfileSample{
		ElapsedMS: time.Since(p.started).Milliseconds(), HeapAlloc: memory.HeapAlloc,
		HeapInuse: memory.HeapInuse, HeapObjects: memory.HeapObjects, TotalAlloc: memory.TotalAlloc,
		Mallocs: memory.Mallocs, Frees: memory.Frees, NumGC: memory.NumGC, Goroutines: runtime.NumGoroutine(),
	})
	if err == nil {
		_, _ = fmt.Fprintln(p.stages, string(encoded))
	}
}

func (p *scannerProfiler) Close() {
	if p == nil {
		return
	}
	p.close.Do(func() {
		close(p.stop)
		<-p.done
		pprof.StopCPUProfile()
		for _, profile := range []struct {
			name string
			kind string
		}{
			{name: "heap", kind: "heap"},
			{name: "allocs", kind: "allocs"},
		} {
			file, err := os.Create(filepath.Join(filepath.Dir(p.stages.Name()), profile.name+".pprof"))
			if err != nil {
				continue
			}
			if lookup := pprof.Lookup(profile.kind); lookup != nil {
				_ = lookup.WriteTo(file, 0)
			}
			_ = file.Close()
		}
		_ = p.stages.Close()
		_ = p.cpu.Close()
	})
}
