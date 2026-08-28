// Package artifactbundle correlates reusable binary Windows artifacts and
// orchestrates standalone SAM + SYSTEM parsing. It is independent of WIM,
// SMB, scanner, and reporting implementations.
package artifactbundle

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"

	"snablr/internal/artifact"
	"snablr/internal/registryhive"
	"snablr/internal/samparse"
	"snablr/internal/systemkey"
)

var (
	ErrClosed          = errors.New("artifact bundle coordinator is closed")
	ErrUnsupportedKind = errors.New("artifact kind is not supported by this coordinator")
	ErrPendingLimit    = errors.New("artifact bundle pending limit reached")
	ErrArtifactLimit   = errors.New("artifact bundle artifact limit reached")
	ErrInvalidArtifact = errors.New("invalid binary artifact")
)

// ParseStatus describes the result of processing a complete SAM + SYSTEM pair.
type ParseStatus uint8

const (
	BundleIncomplete ParseStatus = iota
	BundleParsed
	BundleMalformed
	BundleUnsupported
	BundleFailed
)

// AddState describes what happened to an artifact submitted to Coordinator.Add.
type AddState uint8

const (
	ArtifactAccepted AddState = iota
	ArtifactDuplicate
	ArtifactWaiting
	ArtifactParsed
	ArtifactMalformed
	ArtifactUnsupported
	ArtifactFailed
	ArtifactRejected
	ArtifactCoordinatorClosed
)

// BundleKey is the normalized identity used to pair artifacts. Scope and
// Context deliberately include container boundaries and WIM image identity.
type BundleKey struct {
	Host    string
	Share   string
	Scope   string
	Context string
}

// BundleOrigin contains non-sensitive provenance for a parsed pair.
type BundleOrigin struct {
	Host          string
	Share         string
	Scope         string
	Context       string
	SourceType    string
	ContainerPath string
	ImageIndex    int
	SAMPath       string
	SYSTEMPath    string
}

// SAMBundleResult contains structured parsing output without formatting hash
// material or creating scanner findings.
type SAMBundleResult struct {
	BundleID           string
	Origin             BundleOrigin
	Status             ParseStatus
	ControlSet         uint32
	Accounts           []samparse.Account
	AccountErrors      []samparse.AccountError
	AccountCount       int
	RecoveredHashCount int
	Failure            error
}

// AddResult reports whether an artifact is waiting, duplicated, or completed a
// parse. Parse failures are represented in Result rather than as an ambiguous
// Add error.
type AddResult struct {
	State  AddState
	Key    BundleKey
	Result *SAMBundleResult
}

// Options bounds retained bundles and concurrent parsing.
type Options struct {
	MaxPendingBundles     int
	MaxArtifactsPerBundle int
	MaxConcurrentParsers  int
}

func (o Options) withDefaults() Options {
	if o.MaxPendingBundles <= 0 {
		o.MaxPendingBundles = 1024
	}
	if o.MaxArtifactsPerBundle <= 0 {
		o.MaxArtifactsPerBundle = 2
	}
	if o.MaxConcurrentParsers <= 0 {
		o.MaxConcurrentParsers = 1
	}
	return o
}

type pendingBundle struct {
	key    BundleKey
	byKind map[artifact.Kind]artifact.Binary
}

// Coordinator owns artifacts after Add accepts them. Rejected artifacts are
// caller-owned and must be closed by the caller. Accepted artifacts are closed
// on pair completion, Flush, or Close.
type Coordinator struct {
	mu         sync.Mutex
	opts       Options
	pending    map[BundleKey]*pendingBundle
	processing map[BundleKey]bool
	closed     bool
	parsers    chan struct{}
}

// New creates a concurrency-safe bundle coordinator.
func New(opts Options) *Coordinator {
	opts = opts.withDefaults()
	return &Coordinator{
		opts:       opts,
		pending:    make(map[BundleKey]*pendingBundle),
		processing: make(map[BundleKey]bool),
		parsers:    make(chan struct{}, opts.MaxConcurrentParsers),
	}
}

// KeyFor normalizes an artifact origin without inspecting its contents.
func KeyFor(origin artifact.Origin) BundleKey {
	key := BundleKey{Host: clean(origin.Host), Share: clean(origin.Share)}
	member := cleanPath(origin.MemberPath)
	container := cleanPath(origin.ContainerPath)
	if strings.EqualFold(origin.ContainerType, "wim") {
		key.Scope = container
		key.Context = fmt.Sprintf("wim-image-%d:%s", origin.ImageIndex, path.Dir(member))
		return key
	}
	logical := member
	if logical == "" {
		logical = container
	}
	key.Scope = path.Dir(logical)
	if key.Scope == "." {
		key.Scope = ""
	}
	key.Context = clean(origin.ContainerType)
	return key
}

// Add accepts SAM or SYSTEM. Once accepted, ownership transfers to the
// coordinator. A complete pair is parsed synchronously under a bounded parser
// semaphore, then both artifacts are closed before the result is returned.
func (c *Coordinator) Add(ctx context.Context, binary artifact.Binary) (AddResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if binary == nil {
		return AddResult{State: ArtifactRejected}, ErrInvalidArtifact
	}
	kind := binary.Kind()
	if kind != artifact.KindSAM && kind != artifact.KindSYSTEM {
		return AddResult{State: ArtifactRejected}, ErrUnsupportedKind
	}
	key := KeyFor(binary.Origin())

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return AddResult{State: ArtifactCoordinatorClosed, Key: key}, ErrClosed
	}
	p := c.pending[key]
	if p == nil {
		if len(c.pending) >= c.opts.MaxPendingBundles {
			c.mu.Unlock()
			return AddResult{State: ArtifactRejected, Key: key}, ErrPendingLimit
		}
		p = &pendingBundle{key: key, byKind: make(map[artifact.Kind]artifact.Binary)}
		c.pending[key] = p
	}
	if _, exists := p.byKind[kind]; exists {
		c.mu.Unlock()
		return AddResult{State: ArtifactDuplicate, Key: key}, nil
	}
	if len(p.byKind) >= c.opts.MaxArtifactsPerBundle {
		c.mu.Unlock()
		return AddResult{State: ArtifactRejected, Key: key}, ErrArtifactLimit
	}
	p.byKind[kind] = binary
	if len(p.byKind) < 2 {
		c.mu.Unlock()
		return AddResult{State: ArtifactWaiting, Key: key}, nil
	}
	delete(c.pending, key)
	c.processing[key] = true
	c.mu.Unlock()

	result := c.parse(ctx, p)
	c.mu.Lock()
	delete(c.processing, key)
	c.mu.Unlock()
	return AddResult{State: stateFor(result.Status), Key: key, Result: result}, nil
}

func stateFor(status ParseStatus) AddState {
	switch status {
	case BundleParsed:
		return ArtifactParsed
	case BundleMalformed:
		return ArtifactMalformed
	case BundleUnsupported:
		return ArtifactUnsupported
	case BundleFailed:
		return ArtifactFailed
	}
	return ArtifactRejected
}

func (c *Coordinator) parse(ctx context.Context, p *pendingBundle) *SAMBundleResult {
	result := &SAMBundleResult{
		BundleID: bundleID(p.key),
		Origin:   originFor(p.key, p.byKind[artifact.KindSAM], p.byKind[artifact.KindSYSTEM]),
	}
	if err := ctx.Err(); err != nil {
		result.Status = BundleFailed
		result.Failure = err
		closeArtifacts(p)
		return result
	}
	select {
	case c.parsers <- struct{}{}:
		defer func() { <-c.parsers }()
	case <-ctx.Done():
		result.Status = BundleFailed
		result.Failure = ctx.Err()
		closeArtifacts(p)
		return result
	}
	system := p.byKind[artifact.KindSYSTEM]
	sam := p.byKind[artifact.KindSAM]
	systemReader, systemCloser, err := system.OpenAt()
	if err != nil {
		result.Status = BundleFailed
		result.Failure = err
		closeArtifacts(p)
		return result
	}
	systemHive, err := registryhive.Open(systemReader, system.Size(), registryhive.Options{})
	if err != nil {
		_ = systemCloser.Close()
		result.Status = BundleMalformed
		result.Failure = err
		closeArtifacts(p)
		return result
	}
	keyResult, err := systemkey.Derive(systemHive)
	_ = systemCloser.Close()
	if err != nil {
		result.Status = BundleMalformed
		result.Failure = err
		closeArtifacts(p)
		return result
	}
	defer clearBootKey(&keyResult.BootKey)
	result.ControlSet = keyResult.ControlSet
	samReader, samCloser, err := sam.OpenAt()
	if err != nil {
		result.Status = BundleFailed
		result.Failure = err
		closeArtifacts(p)
		return result
	}
	samHive, err := registryhive.Open(samReader, sam.Size(), registryhive.Options{})
	if err != nil {
		_ = samCloser.Close()
		result.Status = BundleMalformed
		result.Failure = err
		closeArtifacts(p)
		return result
	}
	parsed, err := samparse.Parse(samparse.Inputs{SAM: samHive, BootKey: keyResult.BootKey})
	_ = samCloser.Close()
	closeArtifacts(p)
	result.Accounts = parsed.Accounts
	result.AccountErrors = parsed.Errors
	result.AccountCount = len(parsed.Accounts)
	for _, account := range parsed.Accounts {
		if account.NT.Status == samparse.HashRecovered {
			result.RecoveredHashCount++
		}
		if account.LM.Status == samparse.HashRecovered {
			result.RecoveredHashCount++
		}
	}
	if err != nil {
		if errors.Is(err, samparse.ErrUnsupportedRevision) || errors.Is(err, samparse.ErrUnsupportedHash) {
			result.Status = BundleUnsupported
		} else {
			result.Status = BundleMalformed
		}
		result.Failure = err
		return result
	}
	result.Status = BundleParsed
	return result
}

// Flush closes all currently incomplete bundles and returns their normalized
// identities. It is deterministic and useful at share/scan scope boundaries.
func (c *Coordinator) Flush() []BundleKey {
	c.mu.Lock()
	pending := make([]*pendingBundle, 0, len(c.pending))
	for key, p := range c.pending {
		pending = append(pending, p)
		delete(c.pending, key)
	}
	c.mu.Unlock()
	keys := make([]BundleKey, 0, len(pending))
	for _, p := range pending {
		keys = append(keys, p.key)
		closeArtifacts(p)
	}
	sort.Slice(keys, func(i, j int) bool { return bundleID(keys[i]) < bundleID(keys[j]) })
	return keys
}

// Close prevents new submissions and closes all incomplete accepted artifacts.
// In-flight parses retain ownership until they finish.
func (c *Coordinator) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	pending := make([]*pendingBundle, 0, len(c.pending))
	for key, p := range c.pending {
		pending = append(pending, p)
		delete(c.pending, key)
	}
	c.mu.Unlock()
	for _, p := range pending {
		closeArtifacts(p)
	}
	return nil
}

// PendingCount returns the number of incomplete retained bundles.
func (c *Coordinator) PendingCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

func closeArtifacts(p *pendingBundle) {
	for _, binary := range p.byKind {
		_ = binary.Close()
	}
}

func clearBootKey(key *[16]byte) {
	for i := range key {
		key[i] = 0
	}
}

func originFor(key BundleKey, sam, system artifact.Binary) BundleOrigin {
	base := system
	if base == nil {
		base = sam
	}
	origin := base.Origin()
	return BundleOrigin{
		Host: key.Host, Share: key.Share, Scope: key.Scope, Context: key.Context,
		SourceType: clean(origin.ContainerType), ContainerPath: origin.ContainerPath,
		ImageIndex: origin.ImageIndex, SAMPath: logicalPath(sam), SYSTEMPath: logicalPath(system),
	}
}

func logicalPath(binary artifact.Binary) string {
	if binary == nil {
		return ""
	}
	origin := binary.Origin()
	if origin.MemberPath != "" {
		return origin.MemberPath
	}
	return origin.ContainerPath
}

func bundleID(key BundleKey) string {
	return strings.Join([]string{key.Host, key.Share, key.Scope, key.Context}, "|")
}

func clean(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func cleanPath(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(value, "\\", "/")))
	value = path.Clean(value)
	if value == "." {
		return ""
	}
	return strings.TrimPrefix(value, "/")
}
