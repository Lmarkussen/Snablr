package ui

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"snablr/internal/metrics"
)

const defaultProgressInterval = 3 * time.Second

type MetricsSource interface {
	Snapshot() metrics.Snapshot
}

type ProgressReporter struct {
	w        io.Writer
	source   MetricsSource
	interval time.Duration

	mu               sync.RWMutex
	targetsTotal     int
	targetsProcessed int
	currentHost      string
	status           string
	started          bool

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

func NewProgressReporter(w io.Writer, source MetricsSource, interval time.Duration) *ProgressReporter {
	if interval <= 0 {
		interval = defaultProgressInterval
	}
	return &ProgressReporter{
		w:        w,
		source:   source,
		interval: interval,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func ShouldShowProgress(outputFormat string) bool {
	switch strings.ToLower(strings.TrimSpace(outputFormat)) {
	case "console", "all":
	default:
		return false
	}
	return isTerminal(os.Stdout) && isTerminal(os.Stderr)
}

func (p *ProgressReporter) Start(ctx context.Context) {
	if p == nil || p.w == nil || p.source == nil {
		return
	}
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return
	}
	p.started = true
	p.mu.Unlock()

	ticker := time.NewTicker(p.interval)
	go func() {
		defer func() {
			ticker.Stop()
			close(p.done)
		}()

		for {
			select {
			case <-ctx.Done():
				p.printFinal()
				return
			case <-p.stop:
				p.printFinal()
				return
			case <-ticker.C:
				p.printLine(false)
			}
		}
	}()
}

func (p *ProgressReporter) SetTargetTotal(total int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if total < 0 {
		total = 0
	}
	p.targetsTotal = total
}

func (p *ProgressReporter) SetCurrentHost(host string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.currentHost = strings.TrimSpace(host)
}

func (p *ProgressReporter) MarkTargetProcessed() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.targetsProcessed++
}

func (p *ProgressReporter) SetStatus(status string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status = strings.TrimSpace(status)
}

func (p *ProgressReporter) Close() {
	if p == nil {
		return
	}
	p.stopOnce.Do(func() {
		close(p.stop)
		p.mu.RLock()
		started := p.started
		p.mu.RUnlock()
		if started {
			<-p.done
		}
	})
}

func (p *ProgressReporter) printFinal() {
	p.printLine(true)
}

func (p *ProgressReporter) printLine(final bool) {
	if p == nil || p.w == nil || p.source == nil {
		return
	}

	p.mu.RLock()
	targetsTotal := p.targetsTotal
	targetsProcessed := p.targetsProcessed
	currentHost := p.currentHost
	status := p.status
	p.mu.RUnlock()

	snapshot := p.source.Snapshot()
	line := fmt.Sprintf(
		"[progress] targets %d/%d | shares %d | files %d | skipped %d | matches %d | host %s",
		targetsProcessed,
		targetsTotal,
		snapshot.Counters.SharesEnumerated,
		snapshot.Counters.FilesVisited,
		snapshot.Counters.FilesSkipped,
		snapshot.Counters.MatchesFound,
		valueOrUnknown(currentHost),
	)
	if status != "" {
		line += " | status " + status
	}
	if final {
		line += "\n"
	}
	_, _ = fmt.Fprint(p.w, line)
	if !final {
		_, _ = fmt.Fprint(p.w, "\n")
	}
}

func valueOrUnknown(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	if runtime.GOOS != "windows" && strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb") {
		return false
	}
	return true
}
