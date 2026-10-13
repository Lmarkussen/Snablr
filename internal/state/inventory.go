package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"path"
	"strings"
	"sync"
	"time"
)

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

// Inventory contains generic incremental identity, status, retry, and access
// semantics. Authoritative persistence is handled by the SQLite store.
type Inventory struct {
	mu           sync.RWMutex
	objects      map[string]ObjectRecord
	access       map[string]AccessObservation
	stats        InventoryStats
	resumeReader SQLiteResumeReader
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
	if i.resumeReader != nil {
		if file, found, err := i.resumeReader.LookupFile(identity.Server, identity.Share, identity.Path); err == nil && found {
			i.objects[key] = ObjectRecord{Key: file.Key, Identity: identity, Size: file.Size, ModifiedAt: file.ModifiedAt, Status: ObjectStatus(file.Status), Semantics: file.Semantics, FirstSeen: file.FirstSeen, LastSeen: file.LastSeen, UpdatedAt: file.UpdatedAt}
		}
	}

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
}

func (i *Inventory) Stats() InventoryStats {
	if i == nil {
		return InventoryStats{}
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.stats
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

// InventoryManager applies semantic transitions through the authoritative store.
type InventoryManager struct {
	inventory *Inventory
	store     SQLiteStateStore
}

func (m *InventoryManager) AttachStore(store SQLiteStateStore, scanID string) {
	if m != nil {
		m.store = store
	}
}

func NewInventoryManagerFromSQLiteReader(reader SQLiteResumeReader, interval time.Duration) *InventoryManager {
	return &InventoryManager{inventory: &Inventory{objects: make(map[string]ObjectRecord), access: make(map[string]AccessObservation), resumeReader: reader}}
}
func NewInMemoryInventory() *Inventory {
	return &Inventory{objects: make(map[string]ObjectRecord), access: make(map[string]AccessObservation)}
}
func NewInMemoryInventoryManager() *InventoryManager {
	return &InventoryManager{inventory: NewInMemoryInventory()}
}
func (m *InventoryManager) Enabled() bool         { return m != nil && m.inventory != nil }
func (m *InventoryManager) Start(context.Context) {}
func (m *InventoryManager) Close() error          { return nil }

func (m *InventoryManager) Prepare(observation FileObservation, credentialContextID, semantics string, forceRescan bool) (SkipDecision, error) {
	if !m.Enabled() {
		return SkipDecision{}, nil
	}
	decision, err := m.inventory.Prepare(observation, credentialContextID, semantics, forceRescan)
	if err == nil && m.store != nil {
		m.inventory.mu.RLock()
		object, ok := m.inventory.objects[decision.Key]
		m.inventory.mu.RUnlock()
		if ok {
			_ = m.store.RecordFile(object.Key, object.Identity.Server, object.Identity.Share, object.Identity.Path, string(object.Status), object.Semantics, object.Size, object.ModifiedAt, object.FirstSeen, object.LastSeen, object.UpdatedAt)
		}
		_ = m.store.RecordAccess(credentialContextID, decision.Key, "accessible", time.Now().UTC(), time.Now().UTC())
	}
	return decision, err
}

func (m *InventoryManager) MarkScanning(key string) {
	if m.Enabled() {
		m.inventory.MarkScanning(key)
		m.storeFile(key)
	}
}

func (m *InventoryManager) MarkCompleted(key string) {
	if m.Enabled() {
		m.inventory.MarkCompleted(key)
		m.storeFile(key)
	}
}

func (m *InventoryManager) MarkFailed(key string) {
	if m.Enabled() {
		m.inventory.MarkFailed(key)
		m.storeFile(key)
	}
}

func (m *InventoryManager) MarkPartial(key string) {
	if m.Enabled() {
		m.inventory.MarkPartial(key)
		m.storeFile(key)
	}
}

func (m *InventoryManager) storeFile(key string) {
	if m.store == nil {
		return
	}
	m.inventory.mu.RLock()
	object, ok := m.inventory.objects[key]
	m.inventory.mu.RUnlock()
	if ok {
		_ = m.store.RecordFile(object.Key, object.Identity.Server, object.Identity.Share, object.Identity.Path, string(object.Status), object.Semantics, object.Size, object.ModifiedAt, object.FirstSeen, object.LastSeen, object.UpdatedAt)
	}
}

func (m *InventoryManager) Stats() InventoryStats {
	if !m.Enabled() {
		return InventoryStats{}
	}
	return m.inventory.Stats()
}
