package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const inventoryVersion = 1

// ObjectStatus describes the last known content-inspection state of an object.
type ObjectStatus string

const (
	ObjectNeverSeen        ObjectStatus = "never_seen"
	ObjectQueued           ObjectStatus = "queued"
	ObjectScanning         ObjectStatus = "scanning"
	ObjectCompleted        ObjectStatus = "completed"
	ObjectFailed           ObjectStatus = "failed"
	ObjectPartial          ObjectStatus = "partial"
	ObjectSkippedUnchanged ObjectStatus = "skipped_unchanged"
)

// FileObservation is metadata collected while enumerating an accessible file.
// It deliberately contains no credential material.
type FileObservation struct {
	Server     string
	Share      string
	Path       string
	Size       int64
	ModifiedAt time.Time
}

// ObjectIdentity is the durable identity used by the first inventory schema.
// SMB2 open FileIds are session-scoped in common servers, so they are not used
// here as cross-run identities.
type ObjectIdentity struct {
	Server string `json:"server"`
	Share  string `json:"share"`
	Path   string `json:"path"`
}

// Key returns a collision-resistant, deterministic key for the identity.
func (i ObjectIdentity) Key() string {
	if i.Server == "" || i.Share == "" || i.Path == "" {
		return ""
	}
	return encodeIdentityPart(i.Server) + encodeIdentityPart(i.Share) + encodeIdentityPart(i.Path)
}

func encodeIdentityPart(value string) string {
	return fmt.Sprintf("%d:%s", len(value), value)
}

func (o FileObservation) Identity() ObjectIdentity {
	return ObjectIdentity{
		Server: NormalizeServer(o.Server),
		Share:  NormalizeShare(o.Share),
		Path:   NormalizePath(o.Path),
	}
}

// ObjectRecord is persisted for each discovered file. Error details are not
// persisted because they can contain server paths or implementation data.
type ObjectRecord struct {
	Key        string         `json:"key"`
	Identity   ObjectIdentity `json:"identity"`
	Size       int64          `json:"size"`
	ModifiedAt time.Time      `json:"modified_at"`
	Status     ObjectStatus   `json:"status"`
	Semantics  string         `json:"semantics"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// AccessObservation records that a credential context reached an object. The
// context ID is a one-way identifier and never contains a credential secret.
type AccessObservation struct {
	CredentialContextID string    `json:"credential_context_id"`
	ObjectKey           string    `json:"object_key"`
	FirstSeen           time.Time `json:"first_seen"`
	LastSeen            time.Time `json:"last_seen"`
	AccessResult        string    `json:"access_result"`
}

type inventoryFile struct {
	Version            int                 `json:"version"`
	UpdatedAt          time.Time           `json:"updated_at"`
	Objects            []ObjectRecord      `json:"objects,omitempty"`
	AccessObservations []AccessObservation `json:"access_observations,omitempty"`
}

// InventoryStats are run-local counters and are not persisted.
type InventoryStats struct {
	Discovered         int64
	Inspected          int64
	SkippedUnchanged   int64
	RescannedChanged   int64
	Retried            int64
	NewAccessibleKnown int64
}

// SkipDecision explains whether a discovered file can reuse a completed
// inspection. A false decision always fails open toward inspection.
type SkipDecision struct {
	Skip                 bool
	Reason               string
	Key                  string
	KnownObject          bool
	NewAccessObservation bool
}

// Inventory is a concurrent, atomically persisted content-scan inventory.
type Inventory struct {
	path    string
	dirty   bool
	mu      sync.RWMutex
	objects map[string]ObjectRecord
	access  map[string]AccessObservation
	stats   InventoryStats
}

// OpenInventory opens an existing inventory or creates an empty in-memory
// inventory when the file does not yet exist. Corrupt or unknown-version data
// is returned as an error so callers can fail open toward scanning.
func OpenInventory(filePath string) (*Inventory, error) {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return nil, fmt.Errorf("incremental inventory path cannot be empty")
	}
	inventory := &Inventory{
		path:    filePath,
		objects: make(map[string]ObjectRecord),
		access:  make(map[string]AccessObservation),
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return inventory, nil
		}
		return nil, fmt.Errorf("read incremental inventory %s: %w", filePath, err)
	}

	var stored inventoryFile
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("parse incremental inventory %s: %w", filePath, err)
	}
	if stored.Version != inventoryVersion {
		return nil, fmt.Errorf("incremental inventory %s uses unsupported version %d", filePath, stored.Version)
	}
	for _, object := range stored.Objects {
		if err := validateObjectRecord(object); err != nil {
			return nil, fmt.Errorf("validate incremental inventory %s: %w", filePath, err)
		}
		if _, exists := inventory.objects[object.Key]; exists {
			return nil, fmt.Errorf("validate incremental inventory %s: duplicate object %s", filePath, object.Key)
		}
		inventory.objects[object.Key] = object
	}
	for _, observation := range stored.AccessObservations {
		if strings.TrimSpace(observation.CredentialContextID) == "" || strings.TrimSpace(observation.ObjectKey) == "" {
			return nil, fmt.Errorf("validate incremental inventory %s: access observation has empty identity", filePath)
		}
		key := accessKey(observation.CredentialContextID, observation.ObjectKey)
		if _, exists := inventory.access[key]; exists {
			return nil, fmt.Errorf("validate incremental inventory %s: duplicate access observation", filePath)
		}
		inventory.access[key] = observation
	}
	return inventory, nil
}

func validateObjectRecord(object ObjectRecord) error {
	if object.Key == "" || object.Key != object.Identity.Key() {
		return fmt.Errorf("object key does not match identity")
	}
	if !validObjectStatus(object.Status) {
		return fmt.Errorf("object %s has unsupported status %q", object.Key, object.Status)
	}
	if object.Semantics == "" {
		return fmt.Errorf("object %s has empty scan semantics", object.Key)
	}
	return nil
}

func validObjectStatus(status ObjectStatus) bool {
	switch status {
	case ObjectNeverSeen, ObjectQueued, ObjectScanning, ObjectCompleted,
		ObjectFailed, ObjectPartial, ObjectSkippedUnchanged:
		return true
	default:
		return false
	}
}

// Save writes a complete snapshot through a same-directory rename. A failed
// or interrupted write leaves the previous inventory intact.
func (i *Inventory) Save() error {
	if i == nil {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.dirty && inventoryFileExists(i.path) {
		return nil
	}

	objects := make([]ObjectRecord, 0, len(i.objects))
	for _, object := range i.objects {
		objects = append(objects, object)
	}
	sort.Slice(objects, func(left, right int) bool { return objects[left].Key < objects[right].Key })
	access := make([]AccessObservation, 0, len(i.access))
	for _, observation := range i.access {
		access = append(access, observation)
	}
	sort.Slice(access, func(left, right int) bool {
		if access[left].ObjectKey == access[right].ObjectKey {
			return access[left].CredentialContextID < access[right].CredentialContextID
		}
		return access[left].ObjectKey < access[right].ObjectKey
	})

	data, err := json.MarshalIndent(inventoryFile{
		Version:            inventoryVersion,
		UpdatedAt:          time.Now().UTC(),
		Objects:            objects,
		AccessObservations: access,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal incremental inventory: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(i.path), 0o700); err != nil {
		return fmt.Errorf("create incremental inventory directory: %w", err)
	}
	tmpPath := i.path + ".tmp"
	keepTemp := false
	defer func() {
		if !keepTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open incremental inventory temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write incremental inventory temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync incremental inventory temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close incremental inventory temp file: %w", err)
	}
	if err := os.Rename(tmpPath, i.path); err != nil {
		return fmt.Errorf("replace incremental inventory: %w", err)
	}
	keepTemp = true
	i.dirty = false
	return nil
}

// Prepare records an accessible object and returns the content-inspection
// decision. Directory enumeration is deliberately outside this API and must
// continue even when this method returns Skip=true.
func (i *Inventory) Prepare(observation FileObservation, credentialContextID, semantics string, forceRescan bool) (SkipDecision, error) {
	if i == nil {
		return SkipDecision{}, nil
	}
	identity := observation.Identity()
	key := identity.Key()
	if key == "" {
		return SkipDecision{}, fmt.Errorf("incremental inventory requires server, share, and path")
	}
	if strings.TrimSpace(credentialContextID) == "" {
		return SkipDecision{}, fmt.Errorf("incremental inventory requires a credential context ID")
	}
	if strings.TrimSpace(semantics) == "" {
		return SkipDecision{}, fmt.Errorf("incremental inventory requires scan semantics")
	}
	now := time.Now().UTC()
	i.mu.Lock()
	defer i.mu.Unlock()

	i.stats.Discovered++
	knownAccess := false
	accessID := accessKey(credentialContextID, key)
	if prior, ok := i.access[accessID]; ok {
		knownAccess = true
		prior.LastSeen = now
		prior.AccessResult = "accessible"
		i.access[accessID] = prior
	} else {
		i.access[accessID] = AccessObservation{
			CredentialContextID: credentialContextID,
			ObjectKey:           key,
			FirstSeen:           now,
			LastSeen:            now,
			AccessResult:        "accessible",
		}
		i.dirty = true
	}

	prior, exists := i.objects[key]
	decision := SkipDecision{Key: key, KnownObject: exists, NewAccessObservation: !knownAccess}
	if exists && !knownAccess {
		i.stats.NewAccessibleKnown++
	}
	if exists && !forceRescan && reusable(prior, observation, identity, semantics) {
		prior.Status = ObjectSkippedUnchanged
		prior.LastSeen = now
		prior.UpdatedAt = now
		i.objects[key] = prior
		i.stats.SkippedUnchanged++
		i.dirty = true
		decision.Skip = true
		decision.Reason = "unchanged completed object"
		return decision, nil
	}

	decision.Reason = reasonForRescan(prior, exists, observation, semantics, forceRescan)
	if exists {
		switch prior.Status {
		case ObjectQueued, ObjectScanning, ObjectFailed, ObjectPartial:
			i.stats.Retried++
		case ObjectCompleted, ObjectSkippedUnchanged:
			if !sameMetadata(prior, observation) {
				i.stats.RescannedChanged++
			}
		}
	}
	if !exists {
		prior.FirstSeen = now
	}
	prior.Key = key
	prior.Identity = identity
	prior.Size = observation.Size
	prior.ModifiedAt = observation.ModifiedAt.UTC()
	prior.Status = ObjectQueued
	prior.Semantics = semantics
	prior.LastSeen = now
	prior.UpdatedAt = now
	i.objects[key] = prior
	i.dirty = true
	return decision, nil
}

func reasonForRescan(prior ObjectRecord, exists bool, observation FileObservation, semantics string, force bool) string {
	if force {
		return "operator forced rescan"
	}
	if !exists || prior.Status == ObjectNeverSeen {
		return "new object"
	}
	switch prior.Status {
	case ObjectFailed:
		return "retry failed object"
	case ObjectPartial:
		return "retry partial object"
	case ObjectQueued, ObjectScanning:
		return "retry interrupted object"
	}
	if prior.Semantics != semantics {
		return "scan semantics changed"
	}
	if !sameMetadata(prior, observation) {
		return "object metadata changed"
	}
	return "previous completion was not reusable"
}

func reusable(prior ObjectRecord, current FileObservation, identity ObjectIdentity, semantics string) bool {
	return (prior.Status == ObjectCompleted || prior.Status == ObjectSkippedUnchanged) &&
		prior.Identity == identity &&
		prior.Semantics == semantics &&
		sameMetadata(prior, current)
}

func sameMetadata(prior ObjectRecord, current FileObservation) bool {
	if prior.Size != current.Size {
		return false
	}
	// An unknown timestamp is not enough evidence to suppress a read.
	return !prior.ModifiedAt.IsZero() && !current.ModifiedAt.IsZero() &&
		prior.ModifiedAt.Equal(current.ModifiedAt.UTC())
}

// MarkScanning records that a prepared object was handed to a worker.
func (i *Inventory) MarkScanning(key string) {
	i.markStatus(key, ObjectScanning, false)
}

func (i *Inventory) MarkCompleted(key string) {
	i.markStatus(key, ObjectCompleted, true)
}

func (i *Inventory) MarkFailed(key string) {
	i.markStatus(key, ObjectFailed, true)
}

func (i *Inventory) MarkPartial(key string) {
	i.markStatus(key, ObjectPartial, true)
}

func (i *Inventory) markStatus(key string, status ObjectStatus, countInspection bool) {
	if i == nil || key == "" {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	object, ok := i.objects[key]
	if !ok {
		return
	}
	object.Status = status
	object.UpdatedAt = time.Now().UTC()
	i.objects[key] = object
	if countInspection {
		i.stats.Inspected++
	}
	i.dirty = true
}

func (i *Inventory) Stats() InventoryStats {
	if i == nil {
		return InventoryStats{}
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.stats
}

func (i *Inventory) Path() string {
	if i == nil {
		return ""
	}
	return i.path
}

func accessKey(contextID, objectKey string) string {
	return encodeIdentityPart(contextID) + objectKey
}

// CredentialContextID returns a deterministic opaque ID from non-secret
// principal metadata. Passwords, hashes, tickets, and caches are excluded.
func CredentialContextID(authMode, username, domain string) string {
	value := strings.ToLower(strings.TrimSpace(authMode)) + "\x00" +
		strings.ToLower(strings.TrimSpace(domain)) + "\x00" +
		strings.ToLower(strings.TrimSpace(username))
	digest := sha256.Sum256([]byte(value))
	return "ctx-" + hex.EncodeToString(digest[:])
}

// SemanticsFingerprint returns a stable SHA-256 fingerprint of the supplied
// JSON-compatible scan semantics. Callers should include only settings that
// affect content inspection.
func SemanticsFingerprint(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// NormalizeServer canonicalizes the server component without changing path
// case. DNS names are case-insensitive; IP addresses are canonicalized.
func NormalizeServer(value string) string {
	value = strings.TrimSpace(value)
	if host, port, err := net.SplitHostPort(value); err == nil {
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		return net.JoinHostPort(host, port)
	}
	value = strings.TrimSuffix(value, ".")
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return strings.ToLower(value)
}

// NormalizeShare canonicalizes SMB share names, which are case-insensitive.
func NormalizeShare(value string) string {
	value = strings.Trim(strings.TrimSpace(value), `/\\`)
	return strings.ToLower(value)
}

// NormalizePath normalizes SMB separators and dot segments while preserving
// case because a Samba-backed share may be configured case-sensitive.
func NormalizePath(value string) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), `\`, "/")
	value = strings.TrimLeft(value, "/")
	clean := path.Clean(value)
	if clean == "." || clean == "/" {
		return ""
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return ""
	}
	return strings.Trim(clean, "/")
}

func inventoryFileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}

// InventoryManager periodically persists an Inventory while a scan is
// running. A queued or scanning object remains retryable if the process is
// interrupted before its completion callback updates the inventory.
type InventoryManager struct {
	inventory *Inventory
	interval  time.Duration

	mu       sync.Mutex
	started  bool
	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

func NewInventoryManager(filePath string, interval time.Duration) (*InventoryManager, error) {
	inventory, err := OpenInventory(filePath)
	if err != nil {
		return nil, err
	}
	if interval <= 0 {
		interval = defaultSaveInterval
	}
	return &InventoryManager{
		inventory: inventory,
		interval:  interval,
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}, nil
}

func (m *InventoryManager) Enabled() bool {
	return m != nil && m.inventory != nil
}

func (m *InventoryManager) Start(ctx context.Context) {
	if !m.Enabled() {
		return
	}
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()

	ticker := time.NewTicker(m.interval)
	go func() {
		defer func() {
			ticker.Stop()
			close(m.doneCh)
		}()
		for {
			select {
			case <-ctx.Done():
				_ = m.Save()
				return
			case <-m.stopCh:
				_ = m.Save()
				return
			case <-ticker.C:
				_ = m.Save()
			}
		}
	}()
}

func (m *InventoryManager) Save() error {
	if !m.Enabled() {
		return nil
	}
	return m.inventory.Save()
}

func (m *InventoryManager) Close() error {
	if m == nil {
		return nil
	}
	m.stopOnce.Do(func() {
		close(m.stopCh)
		m.mu.Lock()
		started := m.started
		m.mu.Unlock()
		if started {
			<-m.doneCh
		}
	})
	return m.Save()
}

func (m *InventoryManager) Prepare(observation FileObservation, credentialContextID, semantics string, forceRescan bool) (SkipDecision, error) {
	if !m.Enabled() {
		return SkipDecision{}, nil
	}
	return m.inventory.Prepare(observation, credentialContextID, semantics, forceRescan)
}

func (m *InventoryManager) MarkScanning(key string) {
	if m.Enabled() {
		m.inventory.MarkScanning(key)
	}
}

func (m *InventoryManager) MarkCompleted(key string) {
	if m.Enabled() {
		m.inventory.MarkCompleted(key)
	}
}

func (m *InventoryManager) MarkFailed(key string) {
	if m.Enabled() {
		m.inventory.MarkFailed(key)
	}
}

func (m *InventoryManager) MarkPartial(key string) {
	if m.Enabled() {
		m.inventory.MarkPartial(key)
	}
}

func (m *InventoryManager) Stats() InventoryStats {
	if !m.Enabled() {
		return InventoryStats{}
	}
	return m.inventory.Stats()
}

func (m *InventoryManager) Path() string {
	if !m.Enabled() {
		return ""
	}
	return m.inventory.Path()
}
