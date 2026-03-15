package metrics

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type PhaseTiming struct {
	Name       string        `json:"name"`
	Duration   time.Duration `json:"duration_ns"`
	DurationMS int64         `json:"duration_ms"`
}

type Counters struct {
	TargetsLoaded    int64 `json:"targets_loaded"`
	TargetsReachable int64 `json:"targets_reachable"`
	SharesEnumerated int64 `json:"shares_enumerated"`
	FilesVisited     int64 `json:"files_visited"`
	FilesSkipped     int64 `json:"files_skipped"`
	FilesRead        int64 `json:"files_read"`
	MatchesFound     int64 `json:"matches_found"`
}

type Snapshot struct {
	StartedAt time.Time     `json:"started_at"`
	EndedAt   time.Time     `json:"ended_at"`
	Counters  Counters      `json:"counters"`
	Phases    []PhaseTiming `json:"phases,omitempty"`
}

type Recorder interface {
	AddTargetsLoaded(int)
	AddTargetsReachable(int)
	AddSharesEnumerated(int)
	IncFilesVisited()
	IncFilesSkipped()
	IncFilesRead()
	AddMatchesFound(int)
	StartPhase(string) *Timer
	Snapshot() Snapshot
}

type Collector struct {
	mu        sync.Mutex
	startedAt time.Time
	endedAt   time.Time
	counters  Counters
	phases    map[string]time.Duration
}

func NewCollector() *Collector {
	return &Collector{
		startedAt: time.Now().UTC(),
		phases:    make(map[string]time.Duration),
	}
}

func (c *Collector) AddTargetsLoaded(n int) {
	c.addCounter(func(counters *Counters) { counters.TargetsLoaded += int64(n) })
}

func (c *Collector) AddTargetsReachable(n int) {
	c.addCounter(func(counters *Counters) { counters.TargetsReachable += int64(n) })
}

func (c *Collector) AddSharesEnumerated(n int) {
	c.addCounter(func(counters *Counters) { counters.SharesEnumerated += int64(n) })
}

func (c *Collector) IncFilesVisited() {
	c.addCounter(func(counters *Counters) { counters.FilesVisited++ })
}

func (c *Collector) IncFilesSkipped() {
	c.addCounter(func(counters *Counters) { counters.FilesSkipped++ })
}

func (c *Collector) IncFilesRead() {
	c.addCounter(func(counters *Counters) { counters.FilesRead++ })
}

func (c *Collector) AddMatchesFound(n int) {
	c.addCounter(func(counters *Counters) { counters.MatchesFound += int64(n) })
}

func (c *Collector) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.endedAt.IsZero() {
		c.endedAt = time.Now().UTC()
	}

	phases := make([]PhaseTiming, 0, len(c.phases))
	for name, duration := range c.phases {
		phases = append(phases, PhaseTiming{
			Name:       name,
			Duration:   duration,
			DurationMS: duration.Milliseconds(),
		})
	}
	sort.Slice(phases, func(i, j int) bool {
		return strings.ToLower(phases[i].Name) < strings.ToLower(phases[j].Name)
	})

	return Snapshot{
		StartedAt: c.startedAt,
		EndedAt:   c.endedAt,
		Counters:  c.counters,
		Phases:    phases,
	}
}

func (c *Collector) addPhaseDuration(phase string, duration time.Duration) {
	if c == nil || strings.TrimSpace(phase) == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.phases[phase] += duration
}

func (c *Collector) addCounter(update func(*Counters)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	update(&c.counters)
}
