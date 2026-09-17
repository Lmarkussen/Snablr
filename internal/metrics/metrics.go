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
	TargetsLoaded               int64 `json:"targets_loaded"`
	TargetsReachable            int64 `json:"targets_reachable"`
	SharesEnumerated            int64 `json:"shares_enumerated"`
	FilesVisited                int64 `json:"files_visited"`
	FilesSkipped                int64 `json:"files_skipped"`
	FilesRead                   int64 `json:"files_read"`
	MatchesFound                int64 `json:"matches_found"`
	IncrementalDiscovered       int64 `json:"incremental_discovered,omitempty"`
	IncrementalInspected        int64 `json:"incremental_inspected,omitempty"`
	IncrementalSkippedUnchanged int64 `json:"incremental_skipped_unchanged,omitempty"`
	IncrementalRescannedChanged int64 `json:"incremental_rescanned_changed,omitempty"`
	IncrementalRetried          int64 `json:"incremental_retried,omitempty"`
	IncrementalNewAccessible    int64 `json:"incremental_new_accessible_known,omitempty"`
	DependencyReloads           int64 `json:"dependency_reloads,omitempty"`
	SMBTransportFailures        int64 `json:"smb_transport_failures,omitempty"`
	SMBReconnectsAttempted      int64 `json:"smb_reconnects_attempted,omitempty"`
	SMBReconnectsSucceeded      int64 `json:"smb_reconnects_succeeded,omitempty"`
	SMBReconnectsFailed         int64 `json:"smb_reconnects_failed,omitempty"`
	SMBOperationsRetried        int64 `json:"smb_operations_retried,omitempty"`
	SMBFilesRecovered           int64 `json:"smb_files_recovered,omitempty"`
	SMBRetryExhausted           int64 `json:"smb_retry_exhausted,omitempty"`
	SMBEnumerationFailures      int64 `json:"smb_enumeration_failures,omitempty"`
	SMBOperationTimeouts        int64 `json:"smb_operation_timeouts,omitempty"`
	SMBAuthFailures             int64 `json:"smb_auth_failures,omitempty"`
	SMBShareFailuresContained   int64 `json:"smb_share_failures_contained,omitempty"`
	SMBShareFailuresAbandoned   int64 `json:"smb_share_failures_abandoned,omitempty"`
	SMBOperationsFastFailed     int64 `json:"smb_operations_fast_failed,omitempty"`
	SMBOperationsResumed        int64 `json:"smb_operations_resumed,omitempty"`
	FinalFailureCount           int64 `json:"final_failure_count,omitempty"`
}

// TransportCounters is the transport recovery accounting contributed by a
// scanner transport. It is defined here so the metrics package stays free of
// transport dependencies.
type TransportCounters struct {
	TransportFailures   int64
	ReconnectsAttempted int64
	ReconnectsSucceeded int64
	ReconnectsFailed    int64
	OperationsRetried   int64
	FilesRecovered      int64
	RetryExhausted      int64
	EnumerationFailures int64
	// OperationTimeouts counts request phases abandoned by the operation bound.
	OperationTimeouts int64
	// AuthFailures counts terminal authentication failures (never retried).
	AuthFailures int64
	// SharesWithheld counts shares temporarily held back from work and
	// SharesAbandoned counts shares whose recovery budget was spent.
	SharesWithheld  int64
	SharesAbandoned int64
	// OperationsFastFailed counts operations that failed without touching the
	// network because containment had already given up on their share/target.
	OperationsFastFailed int64
	// OperationsResumed counts operations that succeeded after being held back
	// by containment.
	OperationsResumed int64
}

type Snapshot struct {
	StartedAt time.Time     `json:"started_at"`
	EndedAt   time.Time     `json:"ended_at"`
	Counters  Counters      `json:"counters"`
	Phases    []PhaseTiming `json:"phases,omitempty"`
	// ReadErrorsLog names the per-scan failure artifact, when one was written.
	ReadErrorsLog string `json:"read_errors_log,omitempty"`
}

type Recorder interface {
	AddTargetsLoaded(int)
	AddTargetsReachable(int)
	AddSharesEnumerated(int)
	IncFilesVisited()
	IncFilesSkipped()
	IncFilesRead()
	IncDependencyReload()
	AddMatchesFound(int)
	AddTransportCounters(TransportCounters)
	SetFailureSummary(total int64, readErrorsLog string)
	StartPhase(string) *Timer
	Snapshot() Snapshot
}

type Collector struct {
	mu            sync.Mutex
	startedAt     time.Time
	endedAt       time.Time
	counters      Counters
	phases        map[string]time.Duration
	readErrorsLog string
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

func (c *Collector) IncDependencyReload() {
	c.addCounter(func(counters *Counters) { counters.DependencyReloads++ })
}

func (c *Collector) AddMatchesFound(n int) {
	c.addCounter(func(counters *Counters) { counters.MatchesFound += int64(n) })
}

// AddTransportCounters accumulates transport recovery accounting for the run.
func (c *Collector) AddTransportCounters(counters TransportCounters) {
	c.addCounter(func(existing *Counters) {
		existing.SMBTransportFailures += counters.TransportFailures
		existing.SMBReconnectsAttempted += counters.ReconnectsAttempted
		existing.SMBReconnectsSucceeded += counters.ReconnectsSucceeded
		existing.SMBReconnectsFailed += counters.ReconnectsFailed
		existing.SMBOperationsRetried += counters.OperationsRetried
		existing.SMBFilesRecovered += counters.FilesRecovered
		existing.SMBRetryExhausted += counters.RetryExhausted
		existing.SMBEnumerationFailures += counters.EnumerationFailures
		existing.SMBOperationTimeouts += counters.OperationTimeouts
		existing.SMBAuthFailures += counters.AuthFailures
		existing.SMBShareFailuresContained += counters.SharesWithheld
		existing.SMBShareFailuresAbandoned += counters.SharesAbandoned
		existing.SMBOperationsFastFailed += counters.OperationsFastFailed
		existing.SMBOperationsResumed += counters.OperationsResumed
	})
}

// SetFailureSummary records the final unresolved failure count and the failure
// artifact path so console and JSON output agree with readErrors.log.
func (c *Collector) SetFailureSummary(total int64, readErrorsLog string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counters.FinalFailureCount = total
	c.readErrorsLog = strings.TrimSpace(readErrorsLog)
}

// SetIncrementalCounters records run-local inventory statistics without
// expanding the Recorder interface used by discovery and scanner packages.
func (c *Collector) SetIncrementalCounters(discovered, inspected, skippedUnchanged, rescannedChanged, retried, newAccessible int64) {
	c.addCounter(func(counters *Counters) {
		counters.IncrementalDiscovered = discovered
		counters.IncrementalInspected = inspected
		counters.IncrementalSkippedUnchanged = skippedUnchanged
		counters.IncrementalRescannedChanged = rescannedChanged
		counters.IncrementalRetried = retried
		counters.IncrementalNewAccessible = newAccessible
	})
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
		StartedAt:     c.startedAt,
		EndedAt:       c.endedAt,
		Counters:      c.counters,
		Phases:        phases,
		ReadErrorsLog: c.readErrorsLog,
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
