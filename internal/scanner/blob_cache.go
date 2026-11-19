package scanner

import "sync"

const (
	// blobCacheMinBytes is the smallest blob worth caching; checks on smaller
	// blobs are cheap.
	blobCacheMinBytes = 16 << 10
	// blobCacheMaxBytes bounds the blob bytes the cache keeps alive.
	blobCacheMaxBytes = 32 << 20
)

// blobQualityCache memoizes pure value-quality checks of large evidence
// blobs. Keys are the blobs themselves, so a hit is an exact match. Entries
// are evicted oldest first once their total size exceeds the bound.
type blobQualityCache struct {
	mu      sync.Mutex
	entries map[string]*blobQualityEntry
	order   []string
	bytes   int
}

type blobQualityEntry struct {
	quality       valueQuality
	qualityKnown  bool
	material      bool
	materialKnown bool
}

var largeBlobQualityCache = &blobQualityCache{}

// cacheableBlob reports whether a blob is large enough to be worth caching and
// small enough not to be kept alive on its own.
func cacheableBlob(blob string) bool {
	return len(blob) >= blobCacheMinBytes && len(blob) <= blobCacheMaxBytes/4
}

func (c *blobQualityCache) connectionQuality(blob string, compute func(string) valueQuality) valueQuality {
	if !cacheableBlob(blob) {
		return compute(blob)
	}
	c.mu.Lock()
	if entry := c.entries[blob]; entry != nil && entry.qualityKnown {
		quality := entry.quality
		c.mu.Unlock()
		return quality
	}
	c.mu.Unlock()
	quality := compute(blob)
	c.mu.Lock()
	entry := c.entryLocked(blob)
	entry.quality, entry.qualityKnown = quality, true
	c.mu.Unlock()
	return quality
}

func (c *blobQualityCache) connectionMaterial(blob string, compute func(string) bool) bool {
	if !cacheableBlob(blob) {
		return compute(blob)
	}
	c.mu.Lock()
	if entry := c.entries[blob]; entry != nil && entry.materialKnown {
		material := entry.material
		c.mu.Unlock()
		return material
	}
	c.mu.Unlock()
	material := compute(blob)
	c.mu.Lock()
	entry := c.entryLocked(blob)
	entry.material, entry.materialKnown = material, true
	c.mu.Unlock()
	return material
}

// entryLocked returns the entry for blob, adding it and evicting the oldest
// entries beyond the size bound. The caller holds c.mu.
func (c *blobQualityCache) entryLocked(blob string) *blobQualityEntry {
	if entry := c.entries[blob]; entry != nil {
		return entry
	}
	if c.entries == nil {
		c.entries = make(map[string]*blobQualityEntry)
	}
	entry := &blobQualityEntry{}
	c.entries[blob] = entry
	c.order = append(c.order, blob)
	c.bytes += len(blob)
	for c.bytes > blobCacheMaxBytes && len(c.order) > 1 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
		c.bytes -= len(oldest)
	}
	return entry
}
