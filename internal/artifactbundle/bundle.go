// Package artifactbundle correlates reusable binary Windows artifacts and
// orchestrates standalone SAM + SYSTEM, SECURITY + SYSTEM, and NTDS.DIT + SYSTEM parsing. It is independent of WIM,
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
	"snablr/internal/ntdsparse"
	"snablr/internal/registryhive"
	"snablr/internal/samparse"
	"snablr/internal/securityparse"
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
	SECURITYPath  string
	NTDSPath      string
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

// SecurityBundleResult contains safe metadata from a SECURITY + SYSTEM pair.
// It deliberately contains no decrypted secret or key bytes.
type SecurityBundleResult struct {
	BundleID            string
	Origin              BundleOrigin
	Status              ParseStatus
	ControlSet          uint32
	Revision            string
	LSAKeyDerived       bool
	SecretsFound        int
	SecretsDecoded      int
	CachedDomainFound   int
	CachedDomainDecoded int
	Secrets             []securityparse.SecretRecord
	CachedDomain        []securityparse.CacheRecord
	Warnings            []string
	Failure             error
}

// NTDSBundleResult contains safe metadata from an NTDS.DIT + SYSTEM pair.
// Recovered hashes are retained only inside ntdsparse account values.
type NTDSBundleResult struct {
	BundleID                  string
	Origin                    BundleOrigin
	Status                    ParseStatus
	DatabaseVersion           uint32
	RowsConsidered            int
	AccountsDiscovered        int
	UserAccounts              int
	MachineAccounts           int
	DisabledAccounts          int
	AccountsWithCurrentNTHash int
	Accounts                  []ntdsparse.Account
	PEKRevision               uint32
	Domain                    string
	Failure                   error
}

// AddResult reports whether an artifact is waiting, duplicated, or completed a
// parse. Parse failures are represented in Result rather than as an ambiguous
// Add error.
type AddResult struct {
	State          AddState
	Key            BundleKey
	Result         *SAMBundleResult
	SecurityResult *SecurityBundleResult
	NTDSResult     *NTDSBundleResult
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
		o.MaxArtifactsPerBundle = 4
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
	bootKeys   map[BundleKey][16]byte
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
		bootKeys:   make(map[BundleKey][16]byte),
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
		key.Context = fmt.Sprintf("wim-image-%d:%s", origin.ImageIndex, artifactScope(member))
		return key
	}
	logical := member
	if logical == "" {
		logical = container
	}
	key.Scope = artifactScope(logical)
	if key.Scope == "." {
		key.Scope = ""
	}
	key.Context = clean(origin.ContainerType)
	return key
}

// artifactScope uses the Windows directory as the common origin for the
// recognized offline artifacts. NTDS.DIT is normally under Windows/NTDS while
// SYSTEM, SAM, and SECURITY are under Windows/System32/config; they still
// belong to one installation. Other paths retain the narrower parent scope.
func artifactScope(logical string) string {
	scope := path.Dir(logical)
	parts := strings.Split(strings.TrimPrefix(logical, "/"), "/")
	for i, part := range parts {
		if strings.EqualFold(part, "windows") && i < len(parts)-1 {
			return path.Join(append(parts[:i+1], "")...)
		}
	}
	return scope
}

// Add accepts SAM, SECURITY, NTDS.DIT, or SYSTEM. Once accepted, ownership transfers to the
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
	if kind != artifact.KindSAM && kind != artifact.KindSYSTEM && kind != artifact.KindSECURITY && kind != artifact.KindNTDS {
		return AddResult{State: ArtifactRejected}, ErrUnsupportedKind
	}
	key := KeyFor(binary.Origin())

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return AddResult{State: ArtifactCoordinatorClosed, Key: key}, ErrClosed
	}
	if kind == artifact.KindSECURITY && c.pending[key] == nil {
		if bootKey, ok := c.bootKeys[key]; ok {
			delete(c.bootKeys, key)
			c.processing[key] = true
			c.mu.Unlock()
			pending := &pendingBundle{key: key, byKind: map[artifact.Kind]artifact.Binary{artifact.KindSECURITY: binary}}
			result := c.parseSecurityWithBootKey(ctx, pending, bootKey, &SecurityBundleResult{
				BundleID: bundleID(key),
				Origin:   originFor(key, binary, nil),
			})
			c.mu.Lock()
			delete(c.processing, key)
			c.mu.Unlock()
			return AddResult{State: stateFor(result.Status), Key: key, SecurityResult: result}, nil
		}
	}
	if kind == artifact.KindSAM && c.pending[key] == nil {
		if bootKey, ok := c.bootKeys[key]; ok {
			delete(c.bootKeys, key)
			c.processing[key] = true
			c.mu.Unlock()
			pending := &pendingBundle{key: key, byKind: map[artifact.Kind]artifact.Binary{artifact.KindSAM: binary}}
			result := c.parseSAMWithBootKey(ctx, pending, bootKey)
			c.mu.Lock()
			delete(c.processing, key)
			c.mu.Unlock()
			return AddResult{State: stateFor(result.Status), Key: key, Result: result}, nil
		}
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
	if p.byKind[artifact.KindSYSTEM] == nil || (p.byKind[artifact.KindSAM] == nil && p.byKind[artifact.KindSECURITY] == nil && p.byKind[artifact.KindNTDS] == nil) {
		c.mu.Unlock()
		return AddResult{State: ArtifactWaiting, Key: key}, nil
	}
	delete(c.pending, key)
	c.processing[key] = true
	c.mu.Unlock()
	if _, hasNTDS := p.byKind[artifact.KindNTDS]; hasNTDS && p.byKind[artifact.KindSAM] == nil && p.byKind[artifact.KindSECURITY] == nil {
		result := c.parseNTDS(ctx, p, true)
		c.mu.Lock()
		delete(c.processing, key)
		c.mu.Unlock()
		return AddResult{State: stateFor(result.Status), Key: key, NTDSResult: result}, nil
	}
	var ntdsResult *NTDSBundleResult
	if p.byKind[artifact.KindNTDS] != nil && (p.byKind[artifact.KindSAM] != nil || p.byKind[artifact.KindSECURITY] != nil) {
		ntdsResult = c.parseNTDS(ctx, p, false)
	}

	if _, hasSAM := p.byKind[artifact.KindSAM]; hasSAM {
		if _, hasSECURITY := p.byKind[artifact.KindSECURITY]; hasSECURITY && p.byKind[artifact.KindSYSTEM] != nil {
			resultSAM, resultSECURITY := c.parseBoth(ctx, p)
			c.mu.Lock()
			delete(c.processing, key)
			c.mu.Unlock()
			return AddResult{State: stateFor(resultSECURITY.Status), Key: key, Result: resultSAM, SecurityResult: resultSECURITY, NTDSResult: ntdsResult}, nil
		}
	}
	if _, ok := p.byKind[artifact.KindSECURITY]; ok {
		result := c.parseSecurity(ctx, p)
		c.mu.Lock()
		delete(c.processing, key)
		c.mu.Unlock()
		return AddResult{State: stateFor(result.Status), Key: key, SecurityResult: result, NTDSResult: ntdsResult}, nil
	}
	result := c.parse(ctx, p)
	c.mu.Lock()
	delete(c.processing, key)
	c.mu.Unlock()
	return AddResult{State: stateFor(result.Status), Key: key, Result: result, NTDSResult: ntdsResult}, nil
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
	c.mu.Lock()
	c.bootKeys[p.key] = keyResult.BootKey
	c.mu.Unlock()
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

func (c *Coordinator) parseBoth(ctx context.Context, p *pendingBundle) (*SAMBundleResult, *SecurityBundleResult) {
	samResult := &SAMBundleResult{BundleID: bundleID(p.key), Origin: originFor(p.key, p.byKind[artifact.KindSAM], p.byKind[artifact.KindSYSTEM])}
	securityResult := &SecurityBundleResult{BundleID: bundleID(p.key), Origin: originFor(p.key, p.byKind[artifact.KindSECURITY], p.byKind[artifact.KindSYSTEM])}
	if err := ctx.Err(); err != nil {
		samResult.Status, samResult.Failure = BundleFailed, err
		securityResult.Status, securityResult.Failure = BundleFailed, err
		closeArtifacts(p)
		return samResult, securityResult
	}
	system := p.byKind[artifact.KindSYSTEM]
	systemReader, systemCloser, err := system.OpenAt()
	if err != nil {
		samResult.Status, samResult.Failure = BundleFailed, err
		securityResult.Status, securityResult.Failure = BundleFailed, err
		closeArtifacts(p)
		return samResult, securityResult
	}
	systemHive, err := registryhive.Open(systemReader, system.Size(), registryhive.Options{})
	if err != nil {
		_ = systemCloser.Close()
		samResult.Status, samResult.Failure = BundleMalformed, err
		securityResult.Status, securityResult.Failure = BundleMalformed, err
		closeArtifacts(p)
		return samResult, securityResult
	}
	keyResult, err := systemkey.Derive(systemHive)
	_ = systemCloser.Close()
	if err != nil {
		samResult.Status, samResult.Failure = BundleMalformed, err
		securityResult.Status, securityResult.Failure = BundleMalformed, err
		closeArtifacts(p)
		return samResult, securityResult
	}
	samResult.ControlSet = keyResult.ControlSet
	securityResult.ControlSet = keyResult.ControlSet
	samReader, samCloser, samErr := p.byKind[artifact.KindSAM].OpenAt()
	if samErr == nil {
		samHive, hiveErr := registryhive.Open(samReader, p.byKind[artifact.KindSAM].Size(), registryhive.Options{})
		if hiveErr == nil {
			parsed, parseErr := samparse.Parse(samparse.Inputs{SAM: samHive, BootKey: keyResult.BootKey})
			samResult.Accounts, samResult.AccountErrors = parsed.Accounts, parsed.Errors
			samResult.AccountCount = len(parsed.Accounts)
			for _, account := range parsed.Accounts {
				if account.NT.Status == samparse.HashRecovered {
					samResult.RecoveredHashCount++
				}
				if account.LM.Status == samparse.HashRecovered {
					samResult.RecoveredHashCount++
				}
			}
			if parseErr == nil {
				samResult.Status = BundleParsed
			} else {
				samResult.Status, samResult.Failure = BundleMalformed, parseErr
			}
		} else {
			samResult.Status, samResult.Failure = BundleMalformed, hiveErr
		}
		_ = samCloser.Close()
	} else {
		samResult.Status, samResult.Failure = BundleFailed, samErr
	}
	parsedSecurity := c.parseSecurityWithBootKey(ctx, &pendingBundle{key: p.key, byKind: map[artifact.Kind]artifact.Binary{artifact.KindSECURITY: p.byKind[artifact.KindSECURITY]}}, keyResult.BootKey, securityResult)
	_ = parsedSecurity
	// The SECURITY helper closed only its supplied artifact; close the complete
	// original bundle here to release any remaining ownership.
	closeArtifacts(p)
	clearBootKey(&keyResult.BootKey)
	return samResult, securityResult
}

func (c *Coordinator) parseSecurity(ctx context.Context, p *pendingBundle) *SecurityBundleResult {
	result := &SecurityBundleResult{
		BundleID: bundleID(p.key),
		Origin:   originFor(p.key, p.byKind[artifact.KindSECURITY], p.byKind[artifact.KindSYSTEM]),
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
	security := p.byKind[artifact.KindSECURITY]
	if system == nil {
		c.mu.Lock()
		bootKey, ok := c.bootKeys[p.key]
		delete(c.bootKeys, p.key)
		c.mu.Unlock()
		if !ok {
			result.Status = BundleFailed
			result.Failure = errors.New("SYSTEM boot key is unavailable for SECURITY pair")
			closeArtifacts(p)
			return result
		}
		return c.parseSecurityWithBootKey(ctx, p, bootKey, result)
	}
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
	c.mu.Lock()
	c.bootKeys[p.key] = keyResult.BootKey
	c.mu.Unlock()
	result.ControlSet = keyResult.ControlSet
	securityReader, securityCloser, err := security.OpenAt()
	if err != nil {
		result.Status = BundleFailed
		result.Failure = err
		closeArtifacts(p)
		return result
	}
	securityHive, err := registryhive.Open(securityReader, security.Size(), registryhive.Options{})
	if err != nil {
		_ = securityCloser.Close()
		closeArtifacts(p)
		result.Status = BundleMalformed
		result.Failure = err
		return result
	}
	parsed, err := securityparse.Parse(securityHive, keyResult.BootKey)
	_ = securityCloser.Close()
	closeArtifacts(p)
	result.Revision = parsed.Revision
	result.LSAKeyDerived = parsed.LSAKeyDerived
	result.SecretsFound = parsed.SecretsFound
	result.SecretsDecoded = parsed.SecretsDecoded
	result.CachedDomainFound = parsed.CachedDomainFound
	result.CachedDomainDecoded = parsed.CachedDomainDecoded
	result.Secrets = parsed.Secrets
	result.CachedDomain = parsed.CachedDomain
	result.Warnings = parsed.Warnings
	if err != nil {
		result.Status = BundleMalformed
		if errors.Is(err, securityparse.ErrUnsupportedRevision) {
			result.Status = BundleUnsupported
		}
		result.Failure = err
		return result
	}
	result.Status = BundleParsed
	return result
}

func (c *Coordinator) parseSAMWithBootKey(ctx context.Context, p *pendingBundle, bootKey [16]byte) *SAMBundleResult {
	result := &SAMBundleResult{BundleID: bundleID(p.key), Origin: originFor(p.key, p.byKind[artifact.KindSAM], nil)}
	if err := ctx.Err(); err != nil {
		result.Status, result.Failure = BundleFailed, err
		closeArtifacts(p)
		return result
	}
	sam := p.byKind[artifact.KindSAM]
	reader, closer, err := sam.OpenAt()
	if err != nil {
		result.Status, result.Failure = BundleFailed, err
		closeArtifacts(p)
		return result
	}
	hive, err := registryhive.Open(reader, sam.Size(), registryhive.Options{})
	if err != nil {
		_ = closer.Close()
		result.Status, result.Failure = BundleMalformed, err
		closeArtifacts(p)
		return result
	}
	parsed, err := samparse.Parse(samparse.Inputs{SAM: hive, BootKey: bootKey})
	_ = closer.Close()
	closeArtifacts(p)
	result.Accounts, result.AccountErrors = parsed.Accounts, parsed.Errors
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
		result.Status, result.Failure = BundleMalformed, err
		if errors.Is(err, samparse.ErrUnsupportedRevision) || errors.Is(err, samparse.ErrUnsupportedHash) {
			result.Status = BundleUnsupported
		}
		return result
	}
	result.Status = BundleParsed
	return result
}

func (c *Coordinator) parseSecurityWithBootKey(ctx context.Context, p *pendingBundle, bootKey [16]byte, result *SecurityBundleResult) *SecurityBundleResult {
	security := p.byKind[artifact.KindSECURITY]
	securityReader, securityCloser, err := security.OpenAt()
	if err != nil {
		result.Status = BundleFailed
		result.Failure = err
		closeArtifacts(p)
		return result
	}
	securityHive, err := registryhive.Open(securityReader, security.Size(), registryhive.Options{})
	if err != nil {
		_ = securityCloser.Close()
		closeArtifacts(p)
		result.Status = BundleMalformed
		result.Failure = err
		return result
	}
	parsed, err := securityparse.Parse(securityHive, bootKey)
	_ = securityCloser.Close()
	closeArtifacts(p)
	result.Revision = parsed.Revision
	result.LSAKeyDerived = parsed.LSAKeyDerived
	result.SecretsFound = parsed.SecretsFound
	result.SecretsDecoded = parsed.SecretsDecoded
	result.CachedDomainFound = parsed.CachedDomainFound
	result.CachedDomainDecoded = parsed.CachedDomainDecoded
	result.Secrets = parsed.Secrets
	result.CachedDomain = parsed.CachedDomain
	result.Warnings = parsed.Warnings
	if err != nil {
		result.Status = BundleMalformed
		if errors.Is(err, securityparse.ErrUnsupportedRevision) {
			result.Status = BundleUnsupported
		}
		result.Failure = err
		return result
	}
	result.Status = BundleParsed
	return result
}

func (c *Coordinator) parseNTDS(ctx context.Context, p *pendingBundle, release bool) *NTDSBundleResult {
	closeOwned := func() {
		if release {
			closeArtifacts(p)
		}
	}
	result := &NTDSBundleResult{BundleID: bundleID(p.key), Origin: originFor(p.key, p.byKind[artifact.KindNTDS], p.byKind[artifact.KindSYSTEM])}
	if err := ctx.Err(); err != nil {
		result.Status, result.Failure = BundleFailed, err
		closeOwned()
		return result
	}
	select {
	case c.parsers <- struct{}{}:
		defer func() { <-c.parsers }()
	case <-ctx.Done():
		result.Status, result.Failure = BundleFailed, ctx.Err()
		closeOwned()
		return result
	}
	system := p.byKind[artifact.KindSYSTEM]
	ntds := p.byKind[artifact.KindNTDS]
	systemReader, systemCloser, err := system.OpenAt()
	if err != nil {
		result.Status, result.Failure = BundleFailed, err
		closeOwned()
		return result
	}
	systemHive, err := registryhive.Open(systemReader, system.Size(), registryhive.Options{})
	if err != nil {
		_ = systemCloser.Close()
		result.Status, result.Failure = BundleMalformed, err
		closeOwned()
		return result
	}
	keyResult, err := systemkey.Derive(systemHive)
	_ = systemCloser.Close()
	if err != nil {
		result.Status, result.Failure = BundleMalformed, err
		closeOwned()
		return result
	}
	reader, closer, err := ntds.OpenAt()
	if err != nil {
		result.Status, result.Failure = BundleFailed, err
		closeOwned()
		return result
	}
	parsed, err := ntdsparse.Parse(ntdsparse.Input{Reader: reader, Size: ntds.Size(), BootKey: keyResult.BootKey, Context: ctx})
	_ = closer.Close()
	clearBootKey(&keyResult.BootKey)
	closeOwned()
	result.DatabaseVersion = parsed.DatabaseVersion
	result.RowsConsidered = parsed.RowsConsidered
	result.AccountsDiscovered = parsed.AccountsDiscovered
	result.UserAccounts = parsed.UserAccounts
	result.MachineAccounts = parsed.MachineAccounts
	result.DisabledAccounts = parsed.DisabledAccounts
	result.AccountsWithCurrentNTHash = parsed.AccountsWithCurrentNT
	result.Accounts = parsed.Accounts
	result.PEKRevision = parsed.PEKRevision
	for _, account := range parsed.Accounts {
		if account.Domain != "" {
			result.Domain = account.Domain
			break
		}
	}
	if err != nil {
		result.Status = BundleMalformed
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
	for key, bootKey := range c.bootKeys {
		clearBootKey(&bootKey)
		delete(c.bootKeys, key)
	}
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
	for key, bootKey := range c.bootKeys {
		clearBootKey(&bootKey)
		delete(c.bootKeys, key)
	}
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

func originFor(key BundleKey, first, second artifact.Binary) BundleOrigin {
	base := second
	if base == nil {
		base = first
	}
	var sam, system, security, ntds artifact.Binary
	for _, binary := range []artifact.Binary{first, second} {
		if binary == nil {
			continue
		}
		switch binary.Kind() {
		case artifact.KindSAM:
			sam = binary
		case artifact.KindSYSTEM:
			system = binary
		case artifact.KindSECURITY:
			security = binary
		case artifact.KindNTDS:
			ntds = binary
		}
	}
	if base == nil {
		base = sam
	}
	if base == nil {
		base = ntds
	}
	origin := base.Origin()
	return BundleOrigin{
		Host: key.Host, Share: key.Share, Scope: key.Scope, Context: key.Context,
		SourceType: clean(origin.ContainerType), ContainerPath: origin.ContainerPath,
		ImageIndex: origin.ImageIndex, SAMPath: logicalPath(sam), SYSTEMPath: logicalPath(system), SECURITYPath: logicalPath(security), NTDSPath: logicalPath(ntds),
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
