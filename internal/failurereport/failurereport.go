// Package failurereport collects the FINAL unresolved failures of one scan so
// they can be summarised in metrics, surfaced on the console, and written to a
// readErrors.log artifact. Recovered transient failures are counted but never
// listed.
package failurereport

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"snablr/internal/smb"
)

// Operation identifies what Snablr was doing when it failed.
type Operation string

const (
	OperationRead        Operation = "read"
	OperationOpen        Operation = "open"
	OperationMount       Operation = "tree connect"
	OperationEnumeration Operation = "directory enumeration"
	OperationInspection  Operation = "content inspection"
	OperationExtraction  Operation = "container extraction"
	OperationUnsupported Operation = "unsupported operation"
)

// Category is the stable failure classification used in reports.
type Category string

const (
	CategoryTransport    Category = "SMB transport"
	CategoryMount        Category = "tree connect"
	CategoryEnumeration  Category = "directory enumeration"
	CategoryAccessDenied Category = "access denied"
	CategoryNotFound     Category = "not found"
	CategoryTimeout      Category = "timeout"
	// CategoryAuthFailure is a terminal authentication failure. It is never
	// retryable: reconnecting with rejected credentials cannot succeed.
	CategoryAuthFailure Category = "authentication"
	CategoryRead        Category = "read failure"
	CategorySizeLimit   Category = "resource/size limit"
	CategoryEncrypted   Category = "encrypted content"
	CategoryUnsupported Category = "unsupported content"
	CategoryMalformed   Category = "malformed content"
	CategoryParser      Category = "parser/inspection failure"
	CategoryOther       Category = "other"
)

// Failure is one final unresolved scan failure.
type Failure struct {
	Target             string
	Share              string
	Path               string
	Operation          Operation
	Category           Category
	Parser             string
	ReadSucceeded      bool
	Attempts           int
	ReconnectAttempted bool
	Recovered          bool
	Retryable          bool
	CoverageImpact     string
	FinalError         string
	ObservedAt         time.Time
}

// Counters mirror the transport recovery accounting for the summary section.
type Counters struct {
	FinalReadFailures        int64
	FinalEnumerationFailures int64
	FinalInspectionFailures  int64
	TransportFailures        int64
	ReconnectsAttempted      int64
	ReconnectsSucceeded      int64
	ReconnectsFailed         int64
	OperationsRetried        int64
	FilesRecovered           int64
	RetryExhausted           int64
	// OperationTimeouts counts request phases abandoned by the operation bound.
	OperationTimeouts int64
	// AuthFailures counts terminal authentication failures (never retried).
	AuthFailures int64
	// SharesWithheld counts shares temporarily held back from work and
	// SharesAbandoned counts shares whose recovery budget was spent.
	SharesWithheld  int64
	SharesAbandoned int64
	// OperationsFastFailed counts operations that failed without a network
	// attempt because containment had already given up on their share/target.
	OperationsFastFailed int64
	// OperationsResumed counts operations that succeeded after being held back
	// by containment.
	OperationsResumed int64
}

// Snapshot is an immutable view of the collected failures.
type Snapshot struct {
	Failures []Failure
	Counters Counters
}

// CoverageIncomplete reports whether any object could not be fully inspected.
func (s Snapshot) CoverageIncomplete() bool {
	return len(s.Failures) > 0
}

// Total returns the number of final failed objects.
func (s Snapshot) Total() int {
	return len(s.Failures)
}

// Collector is a concurrency-safe accumulation of final failures.
type Collector struct {
	mu       sync.Mutex
	failures map[string]Failure
	counters Counters
}

func NewCollector() *Collector {
	return &Collector{failures: map[string]Failure{}}
}

// Record adds one final failure. Records are keyed by operation plus logical
// path so repeated observations of the same failure cannot duplicate an entry.
func (c *Collector) Record(failure Failure) {
	if c == nil {
		return
	}
	if failure.Attempts <= 0 {
		failure.Attempts = 1
	}
	if failure.ObservedAt.IsZero() {
		failure.ObservedAt = time.Now().UTC()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := failureKey(failure)
	if existing, ok := c.failures[key]; ok {
		// Keep the strongest attempt record for the same logical failure.
		if existing.Attempts < failure.Attempts {
			existing.Attempts = failure.Attempts
		}
		existing.ReconnectAttempted = existing.ReconnectAttempted || failure.ReconnectAttempted
		c.failures[key] = existing
		return
	}
	c.failures[key] = failure
}

// RecordTransportCounters folds transport recovery accounting into the summary.
func (c *Collector) RecordTransportCounters(counters Counters) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counters.TransportFailures += counters.TransportFailures
	c.counters.ReconnectsAttempted += counters.ReconnectsAttempted
	c.counters.ReconnectsSucceeded += counters.ReconnectsSucceeded
	c.counters.ReconnectsFailed += counters.ReconnectsFailed
	c.counters.OperationsRetried += counters.OperationsRetried
	c.counters.FilesRecovered += counters.FilesRecovered
	c.counters.RetryExhausted += counters.RetryExhausted
	c.counters.OperationTimeouts += counters.OperationTimeouts
	c.counters.AuthFailures += counters.AuthFailures
	c.counters.SharesWithheld += counters.SharesWithheld
	c.counters.SharesAbandoned += counters.SharesAbandoned
	c.counters.OperationsFastFailed += counters.OperationsFastFailed
	c.counters.OperationsResumed += counters.OperationsResumed
}

func (c *Collector) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	failures := make([]Failure, 0, len(c.failures))
	counters := c.counters
	for _, failure := range c.failures {
		failures = append(failures, failure)
		switch failure.Operation {
		case OperationEnumeration:
			counters.FinalEnumerationFailures++
		case OperationInspection:
			counters.FinalInspectionFailures++
		default:
			counters.FinalReadFailures++
		}
	}
	sort.Slice(failures, func(i, j int) bool {
		if failures[i].Path != failures[j].Path {
			return failures[i].Path < failures[j].Path
		}
		return failures[i].Operation < failures[j].Operation
	})
	return Snapshot{Failures: failures, Counters: counters}
}

func failureKey(failure Failure) string {
	return string(failure.Operation) + "\x00" + strings.ToLower(strings.TrimSpace(failure.Path)) + "\x00" + string(failure.Category)
}

// Render writes the deterministic readErrors.log body.
func Render(snapshot Snapshot) string {
	var builder strings.Builder
	builder.WriteString("SNABLR READ ERRORS\n")
	builder.WriteString("==================\n\n")
	builder.WriteString("SUMMARY\n")
	builder.WriteString("-------\n\n")
	fmt.Fprintf(&builder, "Final unreadable files: %d\n", snapshot.Counters.FinalReadFailures)
	fmt.Fprintf(&builder, "Failed directory enumerations: %d\n", snapshot.Counters.FinalEnumerationFailures)
	fmt.Fprintf(&builder, "Failed content inspections: %d\n", snapshot.Counters.FinalInspectionFailures)
	fmt.Fprintf(&builder, "SMB transport failures observed: %d\n", snapshot.Counters.TransportFailures)
	fmt.Fprintf(&builder, "Reconnect attempts: %d\n", snapshot.Counters.ReconnectsAttempted)
	fmt.Fprintf(&builder, "Reconnect successes: %d\n", snapshot.Counters.ReconnectsSucceeded)
	fmt.Fprintf(&builder, "Reconnect failures: %d\n", snapshot.Counters.ReconnectsFailed)
	fmt.Fprintf(&builder, "Operations retried: %d\n", snapshot.Counters.OperationsRetried)
	fmt.Fprintf(&builder, "Files recovered after reconnect: %d\n", snapshot.Counters.FilesRecovered)
	fmt.Fprintf(&builder, "Retry budget exhausted: %d\n", snapshot.Counters.RetryExhausted)
	fmt.Fprintf(&builder, "Operations abandoned by timeout: %d\n", snapshot.Counters.OperationTimeouts)
	fmt.Fprintf(&builder, "Authentication failures: %d\n", snapshot.Counters.AuthFailures)
	fmt.Fprintf(&builder, "Shares withheld from work: %d\n", snapshot.Counters.SharesWithheld)
	fmt.Fprintf(&builder, "Shares abandoned (coverage lost): %d\n", snapshot.Counters.SharesAbandoned)
	fmt.Fprintf(&builder, "Operations failed without a network attempt: %d\n", snapshot.Counters.OperationsFastFailed)
	fmt.Fprintf(&builder, "Operations resumed after containment: %d\n", snapshot.Counters.OperationsResumed)
	fmt.Fprintf(&builder, "Coverage incomplete: %s\n\n", yesNo(snapshot.CoverageIncomplete()))

	builder.WriteString("FINAL FAILED OBJECTS\n")
	builder.WriteString("--------------------\n")
	if len(snapshot.Failures) == 0 {
		builder.WriteString("\n# No final failures: every object was read and inspected.\n")
		return builder.String()
	}
	for _, failure := range snapshot.Failures {
		builder.WriteString("\n")
		fmt.Fprintf(&builder, "Path: %s\n", displayPath(failure))
		fmt.Fprintf(&builder, "Operation: %s\n", failure.Operation)
		if failure.Parser != "" {
			fmt.Fprintf(&builder, "Parser: %s\n", failure.Parser)
		}
		if failure.Operation == OperationInspection {
			fmt.Fprintf(&builder, "Read succeeded: %s\n", yesNo(failure.ReadSucceeded))
		}
		fmt.Fprintf(&builder, "Failure category: %s\n", failure.Category)
		if failure.CoverageImpact != "" {
			fmt.Fprintf(&builder, "Coverage impact: %s\n", failure.CoverageImpact)
		}
		fmt.Fprintf(&builder, "Attempts: %d\n", failure.Attempts)
		fmt.Fprintf(&builder, "Reconnect attempted: %s\n", yesNo(failure.ReconnectAttempted))
		fmt.Fprintf(&builder, "Recovered: %s\n", yesNo(failure.Recovered))
		fmt.Fprintf(&builder, "Retryable next scan: %s\n", yesNo(failure.Retryable))
		fmt.Fprintf(&builder, "Final error: %s\n", Sanitize(failure.FinalError))
		builder.WriteString("\n---\n")
	}
	return builder.String()
}

// WriteFile writes readErrors.log with mode 0600. It removes an existing
// artifact when there is nothing to report, so a healthy scan never leaves a
// stale file behind.
func WriteFile(path string, snapshot Snapshot) (bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return false, nil
	}
	if !snapshot.CoverageIncomplete() {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		return false, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return false, err
	}
	if _, err := io.WriteString(file, Render(snapshot)); err != nil {
		_ = file.Close()
		return false, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return false, err
	}
	return true, file.Close()
}

func displayPath(failure Failure) string {
	path := strings.TrimSpace(failure.Path)
	if failure.Target == "" {
		return path
	}
	if path == "" {
		return failure.Target
	}
	// Logical container members keep their own separators; the SMB portion is
	// rendered with Windows separators like the rest of Snablr's output.
	if strings.Contains(path, "!") {
		return failure.Target + `\` + strings.ReplaceAll(path, "/", `\`)
	}
	return failure.Target + `\` + strings.ReplaceAll(path, "/", `\`)
}

func yesNo(value bool) string {
	if value {
		return "YES"
	}
	return "NO"
}

var secretMarkers = []string{"password", "nt hash", "nthash", "krb5", "ticket", "private key", "api_key", "api key", "token", "secret"}

// Sanitize keeps failure detail useful while guaranteeing that credential
// material can never be rendered into the artifact: any detail that contains an
// authentication marker is replaced by a neutral description, and control
// characters are stripped so the log stays valid UTF-8 text.
func Sanitize(detail string) string {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return "(no detail)"
	}
	lower := strings.ToLower(detail)
	for _, marker := range secretMarkers {
		if strings.Contains(lower, marker) {
			return "(detail withheld: potential credential material)"
		}
	}
	var builder strings.Builder
	for _, r := range detail {
		if r == '\t' || r == '\n' || r == '\r' {
			builder.WriteByte(' ')
			continue
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		builder.WriteRune(r)
	}
	return strings.TrimSpace(builder.String())
}

// CategoryForSMBCategory maps a transport error category into the report
// vocabulary.
func CategoryForSMBCategory(category smb.ErrorCategory) Category {
	switch category {
	case smb.CategoryTransport:
		return CategoryTransport
	case smb.CategoryMount:
		return CategoryMount
	case smb.CategoryEnumeration:
		return CategoryEnumeration
	case smb.CategoryAccessDenied:
		return CategoryAccessDenied
	case smb.CategoryNotFound:
		return CategoryNotFound
	case smb.CategoryTimeout:
		return CategoryTimeout
	case smb.CategoryAuthFailure:
		return CategoryAuthFailure
	case smb.CategorySizeLimit:
		return CategorySizeLimit
	case smb.CategoryRead:
		return CategoryRead
	default:
		return CategoryOther
	}
}
