package dbinspect

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

func seededSQLiteFixture(seed int64, valid bool) []byte {
	rng := rand.New(rand.NewSource(seed))
	pageSize := []int{512, 1024, 2048, 4096}[rng.Intn(4)]
	content := make([]byte, pageSize)
	copy(content, []byte("SQLite format 3\x00"))
	binary.BigEndian.PutUint16(content[16:18], uint16(pageSize))
	content[18], content[19] = 1, 1
	content[20], content[21], content[22], content[23] = 0, 64, 32, 32
	binary.BigEndian.PutUint32(content[28:32], 1)
	if valid {
		return content
	}
	switch rng.Intn(3) {
	case 0:
		content[21] = 63
	case 1:
		binary.BigEndian.PutUint16(content[16:18], 1000)
	case 2:
		content = content[:99]
	}
	return content
}

func TestSeededSQLiteArtifactCorpusIndependentManifest(t *testing.T) {
	t.Parallel()

	seeds := []int64{20261026, 20261027, 20261028, 20261029}
	for _, seed := range seeds {
		seed := seed
		t.Run("seed", func(t *testing.T) {
			valid := seededSQLiteFixture(seed, true)
			invalid := seededSQLiteFixture(seed, false)
			positive := New().InspectContent(Candidate{FilePath: "opaque-copy", Name: "opaque-copy"}, valid)
			negative := New().InspectContent(Candidate{FilePath: "report.db", Name: "report.db"}, invalid)
			if !hasMatchID(positive, "dbinspect.artifact.sqlite_structural") {
				t.Fatalf("seed %d: valid fixture was missed: %#v", seed, positive)
			}
			if hasMatchID(negative, "dbinspect.artifact.sqlite_structural") {
				t.Fatalf("seed %d: invalid fixture was confirmed: %#v", seed, negative)
			}
		})
	}
}
