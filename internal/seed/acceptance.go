package seed

import (
	"fmt"
	"strings"
)

// ValidateGroundTruthFiles verifies the fields required for a locked
// acceptance campaign before any fixture is written to SMB.
func ValidateGroundTruthFiles(files []SeedFile) error {
	if len(files) == 0 {
		return fmt.Errorf("acceptance manifest validation failed: no fixtures generated")
	}

	fixtureIDs := make(map[string]int, len(files))
	paths := make(map[string]int, len(files))
	for index, file := range files {
		location := fmt.Sprintf("fixture %d", index+1)
		require := func(value, field string) error {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s (%s): missing %s", location, file.FixtureID, field)
			}
			return nil
		}
		for field, value := range map[string]string{
			"fixture_id":                     file.FixtureID,
			"category":                       file.Category,
			"format":                         file.Format,
			"relative_path":                  file.RelativePath,
			"intended_as":                    file.IntendedAs,
			"expected_class":                 file.ExpectedClass,
			"expected_triage_class":          file.ExpectedTriageClass,
			"expected_owner":                 file.ExpectedOwner,
			"expected_finder_category":       file.ExpectedFinderCategory,
			"expected_provenance":            file.ExpectedProvenance,
			"expected_grouping":              file.ExpectedGrouping,
			"expected_correlation_semantics": file.ExpectedCorrelationSemantics,
			"support_status":                 file.SupportStatus,
			"expected_justification":         file.ExpectedJustification,
		} {
			if err := require(value, field); err != nil {
				return err
			}
		}
		if previous, exists := fixtureIDs[file.FixtureID]; exists {
			return fmt.Errorf("acceptance manifest validation failed: duplicate fixture_id %q at fixtures %d and %d", file.FixtureID, previous+1, index+1)
		}
		fixtureIDs[file.FixtureID] = index
		path := strings.TrimSpace(file.ExpectedPath)
		if path == "" {
			path = strings.TrimSpace(FullPath(file))
		}
		if previous, exists := paths[path]; exists {
			return fmt.Errorf("acceptance manifest validation failed: duplicate source path %q at fixtures %d and %d", path, previous+1, index+1)
		}
		paths[path] = index

		if file.ExpectedObservations < 0 || file.ExpectedPairs < 0 {
			return fmt.Errorf("%s (%s): expected counts cannot be negative", location, file.FixtureID)
		}
		if file.ExpectedArchive && !strings.Contains(strings.TrimSpace(file.ExpectedPath), "!") && !strings.Contains(strings.TrimSpace(file.ExpectedPath), "::") {
			return fmt.Errorf("%s (%s): archive expectation requires an explicit member path", location, file.FixtureID)
		}
		triage := strings.ToLower(strings.TrimSpace(file.ExpectedTriageClass))
		class := strings.ToLower(strings.TrimSpace(file.ExpectedClass))
		support := strings.ToLower(strings.TrimSpace(file.SupportStatus))
		if support != "supported" && support != "unsupported" && support != "ambiguous" {
			return fmt.Errorf("%s (%s): support_status must be supported, unsupported, or ambiguous", location, file.FixtureID)
		}
		if support == "unsupported" && file.ExpectedObservations != 0 {
			return fmt.Errorf("%s (%s): unsupported fixture cannot expect observations", location, file.FixtureID)
		}
		if file.ExpectedObservations == 0 && (triage == seedTriageActionable || class == seedClassActionable || class == seedClassCorrelatedHighConfidence || class == "credential") {
			return fmt.Errorf("%s (%s): zero expected observations contradict actionable/credential classification", location, file.FixtureID)
		}
		if file.ExpectedObservations > 0 {
			if strings.TrimSpace(file.ExpectedOrigin) == "" {
				return fmt.Errorf("%s (%s): positive expectation requires expected_origin", location, file.FixtureID)
			}
			if strings.TrimSpace(file.ExpectedPairing) == "" {
				return fmt.Errorf("%s (%s): positive expectation requires expected_pairing", location, file.FixtureID)
			}
			if !file.ExpectedInspectable {
				return fmt.Errorf("%s (%s): positive expectation must be inspectable", location, file.FixtureID)
			}
		} else if strings.TrimSpace(file.NegativeReason) == "" && class != "unsupported" {
			return fmt.Errorf("%s (%s): zero expected observations requires negative_reason or unsupported classification", location, file.FixtureID)
		}
		if file.ExpectedPairs > file.ExpectedObservations {
			return fmt.Errorf("%s (%s): expected_pairs exceeds expected_observations", location, file.FixtureID)
		}
		if file.ExpectedCorrelated && file.ExpectedObservations == 0 {
			return fmt.Errorf("%s (%s): correlated expectation requires observations", location, file.FixtureID)
		}
	}
	return nil
}
