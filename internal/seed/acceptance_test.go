package seed

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
)

func validAcceptanceFile() SeedFile {
	return SeedFile{
		Category:                     "database",
		Format:                       "ini",
		RelativePath:                 "campaign/positive.ini",
		Filename:                     "positive.ini",
		IntendedAs:                   "database-positive",
		ExpectedClass:                seedClassActionable,
		ExpectedTriageClass:          seedTriageActionable,
		ExpectedOrigin:               "Database",
		ExpectedPairing:              "same database section",
		ExpectedObservations:         1,
		ExpectedInspectable:          true,
		ExpectedOwner:                "database",
		ExpectedFinderCategory:       "database",
		ExpectedProvenance:           "source file",
		ExpectedGrouping:             "independent observation",
		ExpectedCorrelationSemantics: "no correlation expected",
		SupportStatus:                "supported",
		ExpectedJustification:        "explicit database connection evidence",
		FixtureID:                    "positive-1",
		Content:                      []byte("[database]\nserver=db\n"),
	}
}

func TestValidateGroundTruthFilesAcceptsCompletePositiveAndNegativeEntries(t *testing.T) {
	positive := validAcceptanceFile()
	negative := SeedFile{
		Category:                     "noise",
		Format:                       "ini",
		RelativePath:                 "campaign/negative.ini",
		Filename:                     "negative.ini",
		IntendedAs:                   "negative-control",
		ExpectedClass:                "negative",
		ExpectedTriageClass:          "supporting",
		ExpectedObservations:         0,
		ExpectedOwner:                "noise",
		ExpectedFinderCategory:       "review/raw",
		ExpectedProvenance:           "source file",
		ExpectedGrouping:             "independent observation",
		ExpectedCorrelationSemantics: "no correlation expected",
		SupportStatus:                "supported",
		ExpectedJustification:        "negative control has no database context",
		FixtureID:                    "negative-1",
		NegativeReason:               "generic password has no database context",
		Content:                      []byte("[defaults]\npassword=not-a-db-secret\n"),
	}

	if err := ValidateGroundTruthFiles([]SeedFile{positive, negative}); err != nil {
		t.Fatalf("expected complete ground truth to validate: %v", err)
	}
}

func TestValidateGroundTruthFilesRejectsIncompleteEntries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*SeedFile)
	}{
		{name: "missing classification", mutate: func(file *SeedFile) { file.ExpectedClass = "" }},
		{name: "missing ownership", mutate: func(file *SeedFile) { file.ExpectedOrigin = "" }},
		{name: "missing pairing", mutate: func(file *SeedFile) { file.ExpectedPairing = "" }},
		{name: "not inspectable", mutate: func(file *SeedFile) { file.ExpectedInspectable = false }},
		{name: "contradictory zero actionable", mutate: func(file *SeedFile) {
			file.ExpectedObservations = 0
			file.ExpectedOrigin = ""
			file.ExpectedPairing = ""
			file.ExpectedInspectable = false
			file.NegativeReason = ""
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := validAcceptanceFile()
			tt.mutate(&file)
			if err := ValidateGroundTruthFiles([]SeedFile{file}); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateGroundTruthFilesRejectsDuplicateIdentityAndPath(t *testing.T) {
	first := validAcceptanceFile()
	second := validAcceptanceFile()
	second.FixtureID = "positive-2"
	if err := ValidateGroundTruthFiles([]SeedFile{first, second}); err == nil {
		t.Fatal("expected duplicate path validation error")
	}

	second.RelativePath = "campaign/positive-2.ini"
	second.FixtureID = first.FixtureID
	if err := ValidateGroundTruthFiles([]SeedFile{first, second}); err == nil {
		t.Fatal("expected duplicate fixture ID validation error")
	}
}

func TestCredentialsV2GeneratorHasCompleteGroundTruth(t *testing.T) {
	files, err := Generate(GenerateOptions{CredentialsV2: true, SeedPrefix: "T2", RandomSeed: 20261026, MaxFiles: 100})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateGroundTruthFiles(files); err != nil {
		t.Fatalf("credentials-v2 corpus must pass strict validation: %v", err)
	}
}

func TestExpandedGeneratorHasCompleteGroundTruthAcrossSeeds(t *testing.T) {
	seenCategories := map[string]bool{}
	for _, seed := range []int64{11, 29, 47, 71} {
		files, err := Generate(GenerateOptions{Expanded: true, SeedPrefix: "Expanded", MaxFiles: 5000, Depth: 3, RandomSeed: seed})
		if err != nil {
			t.Fatal(err)
		}
		if len(files) < 100 {
			t.Fatalf("seed %d generated only %d files", seed, len(files))
		}
		if err := ValidateGroundTruthFiles(files); err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		for _, file := range files {
			seenCategories[file.Category] = true
		}
	}
	for _, category := range []string{"evidence-powershell", "evidence-ssh", "evidence-nt-hash", "evidence-sccm", "evidence-office", "negative-placeholder", "wide-tree"} {
		if !seenCategories[category] {
			t.Fatalf("expanded corpus missing category %q", category)
		}
	}
}

func TestValidateGroundTruthFilesRejectsMissingContractMetadata(t *testing.T) {
	file := validAcceptanceFile()
	file.ExpectedJustification = ""
	if err := ValidateGroundTruthFiles([]SeedFile{file}); err == nil {
		t.Fatal("expected missing justification rejection")
	}
}

func TestExpandedManifestLocksDeterministicallyAcrossIndependentSeeds(t *testing.T) {
	seenChecksums := map[[32]byte]bool{}
	for _, seed := range []int64{20261041, 20261042, 20261043, 20261044} {
		files, err := Generate(GenerateOptions{Expanded: true, SeedPrefix: "Locked", MaxFiles: 160, Depth: 3, RandomSeed: seed})
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateGroundTruthFiles(files); err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		entries := make([]SeedManifestEntry, 0, len(files))
		for _, file := range files {
			entries = append(entries, SeedManifestEntry{
				Path: file.ExpectedPath, Category: file.Category, Format: file.Format,
				IntendedAs: file.IntendedAs, ExpectedClass: file.ExpectedClass,
				ExpectedTriageClass: file.ExpectedTriageClass, ExpectedPairing: file.ExpectedPairing,
				ExpectedOrigin: file.ExpectedOrigin, ExpectedPairs: file.ExpectedPairs,
				ExpectedObservations: file.ExpectedObservations, ExpectedInspectable: file.ExpectedInspectable,
				ExpectedArchive: file.ExpectedArchive, FixtureID: file.FixtureID,
				ExpectedOwner: file.ExpectedOwner, ExpectedFinderCategory: file.ExpectedFinderCategory,
				ExpectedProvenance: file.ExpectedProvenance, ExpectedGrouping: file.ExpectedGrouping,
				ExpectedCorrelationSemantics: file.ExpectedCorrelationSemantics,
				SeedVariant:                  file.SeedVariant,
				SupportStatus:                file.SupportStatus, ExpectedJustification: file.ExpectedJustification,
				NegativeReason: file.NegativeReason,
			})
		}
		manifest := Manifest{FixtureVersion: "expanded-smb-fixtures-v1", SeedPrefix: "Locked", Entries: entries}
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		checksum := sha256.Sum256(data)
		t.Logf("seed=%d files=%d manifest_sha256=%x", seed, len(files), checksum)
		if seenChecksums[checksum] {
			t.Fatalf("seed %d reused a manifest checksum", seed)
		}
		seenChecksums[checksum] = true
	}
}
