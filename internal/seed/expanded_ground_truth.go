package seed

import "strings"

// expandedGroundTruth is the acceptance contract for the deterministic
// expanded corpus. It is intentionally based on fixture semantics, never on
// scanner output.
func expandedGroundTruth(category, format, filename, content string, archive bool) SeedFile {
	file := SeedFile{
		Category: category, Format: format, IntendedAs: "expanded-unsupported-control",
		ExpectedClass: "unsupported", ExpectedTriageClass: "supporting",
		ExpectedConfidence: "none", ExpectedSeverity: "informational",
		ExpectedPairs: 0, ExpectedObservations: 0,
		ExpectedInspectable: false, ExpectedArchive: archive,
		ExpectedOrigin:  "fixture generator",
		ExpectedPairing: "not applicable",
		ExpectedOwner:   category, ExpectedFinderCategory: "review/raw",
		ExpectedProvenance:           "source file",
		ExpectedGrouping:             "independent observation",
		ExpectedCorrelationSemantics: "no correlation expected",
		SupportStatus:                "unsupported",
		ExpectedJustification:        "structural control or unsupported acceptance grammar; no scanner observation is expected",
		NegativeReason:               "fixture is not an independently validated supported positive",
	}

	lower := strings.ToLower(category + " " + filename + " " + format + " " + content)
	positive := strings.Contains(category, "evidence-") &&
		!strings.Contains(lower, "negative") &&
		!strings.Contains(category, "manifest")
	review := strings.Contains(category, "sccm") || strings.Contains(category, "vpn") ||
		strings.Contains(category, "browser") || strings.Contains(category, "windows") ||
		strings.Contains(category, "sqlite")
	if positive && !review {
		file.IntendedAs = "expanded-supported-positive"
		file.ExpectedClass = "actionable"
		file.ExpectedTriageClass = "actionable"
		file.ExpectedConfidence = "high"
		file.ExpectedSeverity = "high"
		file.ExpectedObservations = 1
		file.ExpectedPairs = 1
		file.ExpectedInspectable = true
		file.ExpectedOrigin = "explicit fixture evidence"
		file.ExpectedPairing = "evidence in one source artifact"
		file.ExpectedFinderCategory = category
		file.SupportStatus = "supported"
		file.ExpectedJustification = "fixture contains an explicitly seeded supported evidence grammar"
		file.NegativeReason = ""
	} else if positive && review {
		file.IntendedAs = "expanded-review-positive"
		file.ExpectedClass = "review"
		file.ExpectedTriageClass = "review"
		file.ExpectedConfidence = "low"
		file.ExpectedSeverity = "low"
		file.ExpectedObservations = 1
		file.ExpectedInspectable = true
		file.ExpectedOrigin = "explicit fixture evidence"
		file.ExpectedPairing = "review evidence in one source artifact"
		file.ExpectedFinderCategory = "review/raw"
		file.SupportStatus = "ambiguous"
		file.ExpectedJustification = "fixture is intentionally review-only and must not be promoted to a confirmed finding"
		file.NegativeReason = ""
	}
	if archive {
		file.ExpectedProvenance = "archive member"
	}
	if strings.Contains(category, "correlation") {
		file.ExpectedGrouping = "independent source observation"
		file.ExpectedCorrelationSemantics = "correlation requires an independently matching companion observation"
	}
	return file
}
