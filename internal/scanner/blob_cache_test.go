package scanner

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func largeConnectionBlob(id int) string {
	var b strings.Builder
	for i := 0; b.Len() < blobCacheMinBytes*2; i++ {
		fmt.Fprintf(&b, "Server=sql%02d.example.invalid;Database=App%d;User Id=svc_app;Password=Synthetic-%d-Pass!%d\n", id, i, id, i)
	}
	return b.String()
}

// Cached checks return exactly what the uncached checks return.
func TestBlobQualityCacheMatchesUncached(t *testing.T) {
	blobs := []string{
		"Server=db;Database=x;Password=Synthetic-Small-1!",
		largeConnectionBlob(1),
		strings.Repeat("no connection material here\n", blobCacheMinBytes/10),
		strings.Repeat("Server=db;Database=x;Password=changeme\n", blobCacheMinBytes/20),
	}
	for i, blob := range blobs {
		for round := 0; round < 2; round++ {
			if got, want := assessConnectionStringQuality(blob), assessConnectionStringQualityUncached(blob); got != want {
				t.Fatalf("blob %d round %d: cached quality %+v, uncached %+v", i, round, got, want)
			}
			if got, want := looksLikeConnectionMaterial(blob), looksLikeConnectionMaterialUncached(blob); got != want {
				t.Fatalf("blob %d round %d: cached material %v, uncached %v", i, round, got, want)
			}
		}
	}
}

// One structured file can yield hundreds of findings carrying the same large
// context; the expensive check runs once for that context.
func TestBlobQualityCacheComputesSharedBlobOnce(t *testing.T) {
	cache := &blobQualityCache{}
	blob := largeConnectionBlob(2)
	calls := 0
	compute := func(b string) valueQuality { calls++; return assessConnectionStringQualityUncached(b) }
	for i := 0; i < 400; i++ {
		cache.connectionQuality(blob, compute)
	}
	if calls != 1 {
		t.Fatalf("computed %d times for one shared blob, want 1", calls)
	}
	small := "Server=db;Database=x;Password=Synthetic-Small-2!"
	for i := 0; i < 3; i++ {
		cache.connectionQuality(small, compute)
	}
	if calls != 4 {
		t.Fatalf("small blobs should not be cached: calls=%d, want 4", calls)
	}
}

func TestBlobQualityCacheStaysWithinBound(t *testing.T) {
	cache := &blobQualityCache{}
	for i := 0; i < 2000; i++ {
		cache.connectionMaterial(largeConnectionBlob(i%97)+fmt.Sprint(i), looksLikeConnectionMaterialUncached)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.bytes > blobCacheMaxBytes || len(cache.entries) != len(cache.order) {
		t.Fatalf("cache bytes=%d entries=%d order=%d, bound %d", cache.bytes, len(cache.entries), len(cache.order), blobCacheMaxBytes)
	}
}

func TestBlobQualityCacheConcurrentUse(t *testing.T) {
	cache := &blobQualityCache{}
	blobs := []string{largeConnectionBlob(3), largeConnectionBlob(4)}
	want := []valueQuality{assessConnectionStringQualityUncached(blobs[0]), assessConnectionStringQualityUncached(blobs[1])}
	var wg sync.WaitGroup
	for w := 0; w < 15; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if got := cache.connectionQuality(blobs[(w+i)%2], assessConnectionStringQualityUncached); got != want[(w+i)%2] {
					t.Errorf("concurrent result differs: %+v", got)
					return
				}
			}
		}(w)
	}
	wg.Wait()
}
